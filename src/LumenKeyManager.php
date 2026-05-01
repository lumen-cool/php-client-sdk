<?php
/** @noinspection PhpUnused */
declare(strict_types=1);

namespace Lumen\Sdk;

use Nyra\Bip39\Bip39;
use Random\RandomException;
use RuntimeException;
use SensitiveParameter;
use SodiumException;

/**
 * LumenKeyManager
 * - BIP39 mnemonic -> seed -> app-scoped master key (HKDF-SHA256)
 * - Per-file key derivation (HKDF-SHA256 with per-file salt)
 * - Deterministic per-chunk IV (96-bit) for AES-GCM
 * - Chunked AES-256-GCM encryption/decryption with AAD
 * - Optional: wrap/unwrap master key with Argon2id (libsodium) for at-rest storage
 */
final class LumenKeyManager
{
    // ---- HKDF "info" roles (contexts) ----
    public const string INFO_MASTER = 'lumen-master-v1';
    public const string INFO_FILE_KEY = 'lumen-file-encryption-v1';
    public const string INFO_META_WRAP = 'lumen-metadata-wrap-v1';
    public const string INFO_SIGNING = 'lumen-signing-v1'; // reserved

    // ---- HKDF salts (app-level, non-secret constants) ----
    public const string SALT_APP = 'lumen-app-salt-v1';
    public const string SALT_SIGNING = 'lumen-signing-salt-v1'; // reserved

    // ---- Cipher parameters ----
    public const string AAD_FILE = 'lumen-file-v1';
    public const int GCM_TAG_LEN = 16;   // bytes
    public const int GCM_IV_LEN = 12;   // 96-bit (recommended for GCM)
    public const int FILE_SALT_LEN = 16;   // per-file random salt

    // ===== ROOT: BIP-39 =====

    /**
     * Derive the 32-byte app master key from a BIP-39 mnemonic (+ optional passphrase).
     * - mnemonicToSeedHex() -> 64-byte seed
     * - HKDF-SHA256(seed, info=INFO_MASTER, salt=SALT_APP, L=32)
     *
     * @throws RuntimeException if the mnemonic is invalid
     */
    public static function deriveMasterKeyFromMnemonic(string $mnemonic, string $bip39Passphrase = ''): string
    {
        if (!Bip39::isValidMnemonic($mnemonic)) {
            throw new RuntimeException('Invalid BIP-39 mnemonic.');
        }
        $seedHex = Bip39::mnemonicToSeedHex($mnemonic, $bip39Passphrase); // 64-byte hex
        $seed = hex2bin($seedHex);
        return hash_hkdf('sha256', $seed, 32, self::INFO_MASTER, self::SALT_APP);
    }

    // ===== PER-FILE KEYS =====

    /**
     * Generate a new per-file salt (store in file metadata).
     *
     * @throws RandomException
     */
    public static function generateFileSalt(): string
    {
        return random_bytes(self::FILE_SALT_LEN);
    }

    /**
     * Derive a 32-byte per-file encryption key from the master key and file salt.
     */
    public static function deriveFileKey(#[SensitiveParameter] string $masterKey, string $fileSalt): string
    {
        return hash_hkdf('sha256', $masterKey, 32, self::INFO_FILE_KEY, $fileSalt);
    }

    /**
     * Generate a new 32-byte (256-bit) random file key.
     *
     * @throws RandomException
     */
    public static function generateRandomFileKey(): string
    {
        return random_bytes(32);
    }

    /**
     * Wrap the file key with the master key.
     * Returns: iv (12 bytes) . ciphertext . tag (16 bytes)
     *
     * @throws RandomException
     */
    public static function wrapFileKey(#[SensitiveParameter] string $fileKey, #[SensitiveParameter] string $masterKey): string
    {
        $iv = random_bytes(self::GCM_IV_LEN);
        $tag = '';
        $ct = openssl_encrypt(
            $fileKey,
            'aes-256-gcm',
            $masterKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::INFO_FILE_KEY,
            self::GCM_TAG_LEN
        );
        if ($ct === false) {
            throw new RuntimeException('openssl_encrypt failed to wrap file key.');
        }


        return $iv . $ct . $tag;
    }

    /**
     * Unwrap the file key with the master key.
     */
    public static function unwrapFileKey(string $wrappedKeyData, #[SensitiveParameter] string $masterKey): string
    {
        if (strlen($wrappedKeyData) < self::GCM_IV_LEN + 32 + self::GCM_TAG_LEN) {
            throw new RuntimeException('Wrapped key data is too short.');
        }

        $iv = substr($wrappedKeyData, 0, self::GCM_IV_LEN);
        $ct = substr($wrappedKeyData, self::GCM_IV_LEN, -self::GCM_TAG_LEN);
        $tag = substr($wrappedKeyData, -self::GCM_TAG_LEN);

        $fileKey = openssl_decrypt(
            $ct,
            'aes-256-gcm',
            $masterKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::INFO_FILE_KEY
        );

        if ($fileKey === false) {
            throw new RuntimeException('Failed to unwrap file key.');
        }

        return $fileKey;
    }

    // ===== CHUNK IVs =====

    /**
     * Generate a new random 96-bit (12-byte) base IV.
     * @throws RandomException
     */
    public static function generateBaseIv(): string
    {
        return random_bytes(self::GCM_IV_LEN);
    }

    /**
     * Derive a unique 96-bit (12-byte) IV for chunk i by XORing the base IV with the chunk index.
     * cks or overwrites share the same nonce.
     */
    public static function deriveChunkIv(string $baseIv, int $chunkIndex): string
    {
        if (strlen($baseIv) !== self::GCM_IV_LEN) {
            throw new RuntimeException('Invalid base IV length.');
        }

        $iv = $baseIv;
        $counter = pack('N', $chunkIndex); // 4-byte chunk index counter

        // XOR the last 4 bytes of the IV
        for ($i = 0; $i < 4; ++$i) {
            $iv[8 + $i] = $iv[8 + $i] ^ $counter[$i];
        }

        return $iv;
    }

    // ===== ENCRYPT / DECRYPT =====

    /**
     * Encrypt a plaintext chunk with AES-256-GCM.
     * Returns binary (ciphertext || 16-byte tag).
     * $aad is optional but recommended; must match on decrypt.
     */
    public static function encryptChunk(string $chunkPlaintext, #[SensitiveParameter] string $fileKey, string $iv, string $aad): string
    {
        $tag = '';
        $ct = openssl_encrypt(
            $chunkPlaintext,
            'aes-256-gcm',
            $fileKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad,
            self::GCM_TAG_LEN
        );
        if ($ct === false) {
            throw new RuntimeException('openssl_encrypt failed.');
        }
        return $ct . $tag;
    }

    /**
     * Decrypt a single encrypted part (ciphertext||tag) with AES-256-GCM.
     * Returns plaintext or throws if authentication fails.
     */
    public static function decryptPart(string $partCipherTag, #[SensitiveParameter] string $fileKey, string $iv, string $aad): string
    {
        if (strlen($partCipherTag) < self::GCM_TAG_LEN) {
            throw new RuntimeException('Encrypted part too short.');
        }
        $ct = substr($partCipherTag, 0, -self::GCM_TAG_LEN);
        $tag = substr($partCipherTag, -self::GCM_TAG_LEN);

        $pt = openssl_decrypt(
            $ct,
            'aes-256-gcm',
            $fileKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad
        );
        if ($pt === false) {
            throw new RuntimeException('Decryption/authentication failed.');
        }
        return $pt;
    }

    /**
     * Stream a file (from a PHP stream resource) into fixed-size plaintext chunks,
     * encrypt each chunk, and hand each (cipher || tag) to a callback (e.g., S3 uploadPart).
     *
     * @param resource $inStream readable stream (e.g., fopen('path', 'rb'))
     * @param int $plaintextChunkSize fixed plaintext chunk size in bytes
     * @param callable $onPart function(int $index, string $cipherTagBlob): void
     */
    public static function encryptStreamToParts($inStream, #[SensitiveParameter] string $fileKey, string $fileSalt, int $plaintextChunkSize, callable $onPart): void
    {
        if (!is_resource($inStream)) {
            throw new RuntimeException('Input is not a valid stream.');
        }
        $i = 0;
        while (!feof($inStream)) {
            $chunk = fread($inStream, $plaintextChunkSize);
            if ($chunk === '' || $chunk === false) {
                break;
            }
            $iv = self::deriveChunkIv($fileSalt, $i);
            $blob = self::encryptChunk($chunk, $fileKey, $iv, self::AAD_FILE);
            $onPart($i, $blob);
            $i++;
        }
    }

    /**
     * Decrypt an ordered iterable of encrypted parts (cipher||tag) into a sink callback.
     *
     * @param iterable $parts yields strings (cipher||tag) in order
     * @param callable $onPlain function(string $plaintext): void
     */
    public static function decryptParts(iterable $parts, #[SensitiveParameter] string $fileKey, string $fileSalt, callable $onPlain): void
    {
        $i = 0;
        foreach ($parts as $blob) {
            $iv = self::deriveChunkIv($fileSalt, $i);
            $pt = self::decryptPart($blob, $fileKey, $iv, self::AAD_FILE);
            $onPlain($pt);
            $i++;
        }
    }

    // ===== OPTIONAL: wrap/unwrap master key under a user password =====

    /**
     * Wrap the master key under a user password using Argon2id -> KEK, then AES-256-GCM.
     * Returns an associative array you can serialize/store.
     * @throws RandomException
     * @throws SodiumException
     */
    public static function wrapMasterKeyWithPassword(#[SensitiveParameter] string $masterKey, #[SensitiveParameter] string $password): array
    {
        if (!function_exists('sodium_crypto_pwhash')) {
            throw new RuntimeException('libsodium (sodium_crypto_pwhash) is required for Argon2id.');
        }
        $salt = random_bytes(16);
        $kek = sodium_crypto_pwhash(
            32,
            $password,
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
        $iv = random_bytes(self::GCM_IV_LEN);
        $tag = '';
        $ct = openssl_encrypt($masterKey, 'aes-256-gcm', $kek, OPENSSL_RAW_DATA, $iv, $tag, 'lumen-kek-v1', self::GCM_TAG_LEN);
        if ($ct === false) throw new RuntimeException('Master key wrap failed.');
        return [
            'v' => 1,
            'salt' => base64_encode($salt),
            'iv' => base64_encode($iv),
            'ct' => base64_encode($ct),
            'tag' => base64_encode($tag),
            'kdf' => 'argon2id-interactive',
            'aad' => 'lumen-kek-v1'
        ];
    }

    /**
     * @throws SodiumException
     */
    public static function unwrapMasterKeyWithPassword(array $blob, #[SensitiveParameter] string $password): string
    {
        if (!function_exists('sodium_crypto_pwhash')) {
            throw new RuntimeException('libsodium (sodium_crypto_pwhash) is required for Argon2id.');
        }
        foreach (['salt', 'iv', 'ct', 'tag'] as $k) {
            if (!isset($blob[$k])) throw new RuntimeException("Missing wrap field: $k");
        }
        $salt = base64_decode($blob['salt']);
        $iv = base64_decode($blob['iv']);
        $ct = base64_decode($blob['ct']);
        $tag = base64_decode($blob['tag']);

        $kek = sodium_crypto_pwhash(
            32,
            $password,
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
        $pt = openssl_decrypt($ct, 'aes-256-gcm', $kek, OPENSSL_RAW_DATA, $iv, $tag, $blob['aad'] ?? 'lumen-kek-v1');
        if ($pt === false) throw new RuntimeException('Master key unwrap failed.');
        return $pt;
    }

    /**
     * Derive a metadata encryption key from the per-file key and file salt.
     */
    public static function deriveMetadataKey(#[SensitiveParameter] string $fileKey, string $fileSalt): string
    {
        return hash_hkdf('sha256', $fileKey, 32, self::INFO_META_WRAP, $fileSalt);
    }

    /**
     * Encrypt a small metadata string (e.g. filename) with AES-256-GCM using a metadata key.
     * Returns a base64-encoded blob of (iv || ciphertext || tag).
     * @throws RandomException
     */
    public static function encryptMetadata(string $plaintext, #[SensitiveParameter] string $fileKey, string $fileSalt): string
    {
        $metaKey = self::deriveMetadataKey($fileKey, $fileSalt);
        $iv = random_bytes(self::GCM_IV_LEN);
        $tag = '';
        $ct = openssl_encrypt($plaintext, 'aes-256-gcm', $metaKey, OPENSSL_RAW_DATA, $iv, $tag, self::INFO_META_WRAP, self::GCM_TAG_LEN);
        if ($ct === false) {
            throw new RuntimeException('Metadata encryption failed.');
        }
        return base64_encode($iv . $ct . $tag);
    }

    /**
     * Decrypt a metadata blob produced by encryptMetadata.
     * Expects a base64-encoded blob of (iv || ciphertext || tag).
     *
     * @throws RuntimeException if the blob is invalid or decryption/authentication fails.
     */
    public static function decryptMetadata(string $blobB64, #[SensitiveParameter] string $fileKey, string $fileSalt): string
    {
        $data = base64_decode($blobB64, true);
        if ($data === false) {
            throw new RuntimeException('Invalid base64 metadata blob.');
        }
        if (strlen($data) < (self::GCM_IV_LEN + self::GCM_TAG_LEN)) {
            throw new RuntimeException('Metadata blob too short.');
        }
        $iv = substr($data, 0, self::GCM_IV_LEN);
        $tag = substr($data, -self::GCM_TAG_LEN);
        $ct = substr($data, self::GCM_IV_LEN, strlen($data) - self::GCM_IV_LEN - self::GCM_TAG_LEN);

        $metaKey = self::deriveMetadataKey($fileKey, $fileSalt);
        $pt = openssl_decrypt($ct, 'aes-256-gcm', $metaKey, OPENSSL_RAW_DATA, $iv, $tag, self::INFO_META_WRAP);
        if ($pt === false) {
            throw new RuntimeException('Metadata decryption/authentication failed.');
        }
        return $pt;
    }
}
