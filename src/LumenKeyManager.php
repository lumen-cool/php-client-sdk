<?php
declare(strict_types=1);

namespace Lumen\Sdk;

use Nyra\Bip39\Bip39;
use Random\RandomException;
use RuntimeException;
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
    public const INFO_MASTER = 'lumen-master-v1';
    public const INFO_FILE_KEY = 'lumen-file-encryption-v1';
    public const INFO_META_WRAP = 'lumen-metadata-wrap-v1';
    public const INFO_SIGNING = 'lumen-signing-v1'; // reserved

    // ---- HKDF salts (app-level, non-secret constants) ----
    public const SALT_APP = 'lumen-app-salt-v1';
    public const SALT_SIGNING = 'lumen-signing-salt-v1'; // reserved

    // ---- Cipher parameters ----
    public const AAD_FILE = 'lumen-file-v1';
    public const GCM_TAG_LEN = 16;   // bytes
    public const GCM_IV_LEN = 12;   // 96-bit (recommended for GCM)
    public const FILE_SALT_LEN = 16;   // per-file random salt

    // ===== ROOT: BIP-39 =====

    /**
     * Derive the 32-byte app master key from a BIP-39 mnemonic (+ optional passphrase).
     * - mnemonicToSeedHex() -> 64-byte seed
     * - HKDF-SHA256(seed, info=INFO_MASTER, salt=SALT_APP, L=32)
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
     * @throws RandomException
     */
    public static function generateFileSalt(): string
    {
        return random_bytes(self::FILE_SALT_LEN);
    }

    /**
     * Derive a 32-byte per-file encryption key from the master key and file salt.
     */
    public static function deriveFileKey(string $masterKey, string $fileSalt): string
    {
        return hash_hkdf('sha256', $masterKey, 32, self::INFO_FILE_KEY, $fileSalt);
    }

    // ===== CHUNK IVs =====

    /**
     * Derive deterministic 96-bit (12-byte) IV for chunk i:
     * IV_i = first 12 bytes of SHA256(fileSalt || uint32_be(i))
     */
    public static function deriveChunkIv(string $fileSalt, int $chunkIndex): string
    {
        return substr(hash('sha256', $fileSalt . pack('N', $chunkIndex), true), 0, self::GCM_IV_LEN);
    }

    // ===== ENCRYPT / DECRYPT =====

    /**
     * Encrypt a plaintext chunk with AES-256-GCM.
     * Returns binary (ciphertext || 16-byte tag).
     * $aad is optional but recommended; must match on decrypt.
     */
    public static function encryptChunk(string $chunkPlaintext, string $fileKey, string $iv, string $aad = self::AAD_FILE): string
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
    public static function decryptPart(string $partCipherTag, string $fileKey, string $iv, string $aad = self::AAD_FILE): string
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
    public static function encryptStreamToParts($inStream, string $fileKey, string $fileSalt, int $plaintextChunkSize, callable $onPart): void
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
            /** @noinspection PhpRedundantOptionalArgumentInspection */
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
    public static function decryptParts(iterable $parts, string $fileKey, string $fileSalt, callable $onPlain): void
    {
        $i = 0;
        foreach ($parts as $blob) {
            $iv = self::deriveChunkIv($fileSalt, $i);
            /** @noinspection PhpRedundantOptionalArgumentInspection */
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
    public static function wrapMasterKeyWithPassword(string $masterKey, string $password): array
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
    public static function unwrapMasterKeyWithPassword(array $blob, string $password): string
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
}
