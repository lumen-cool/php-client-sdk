<?php
declare(strict_types=1);

namespace Lumen\Sdk\Tests;

use Lumen\Sdk\LumenKeyManager;
use Nyra\Bip39\Bip39;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use RuntimeException;

class LumenKeyManagerTest extends TestCase
{
    private string $masterKey;
    private string $fileSalt;
    private string $fileKey;

    /**
     * @throws RandomException
     */
    protected function setUp(): void
    {
        $mnemonic = Bip39::generateMnemonic();
        $this->masterKey = LumenKeyManager::deriveMasterKeyFromMnemonic($mnemonic);
        $this->fileSalt = LumenKeyManager::generateFileSalt();
        $this->fileKey = LumenKeyManager::deriveFileKey($this->masterKey, $this->fileSalt);
    }

    public function testDeriveMasterKeyFromMnemonicThrowsOnInvalidMnemonic(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid BIP-39 mnemonic.');
        LumenKeyManager::deriveMasterKeyFromMnemonic('invalid mnemonic given here');
    }

    /**
     * @throws RandomException
     */
    public function testDeriveMasterKeyFromMnemonicSucceeds(): void
    {
        $mnemonic = Bip39::generateMnemonic();
        $key = LumenKeyManager::deriveMasterKeyFromMnemonic($mnemonic);
        $this->assertEquals(32, strlen($key));
    }

    /**
     * @throws RandomException
     */
    public function testWrapAndUnwrapFileKey(): void
    {
        $wrapped = LumenKeyManager::wrapFileKey($this->fileKey, $this->masterKey);
        // IV (12) + tag (16) + key length (32) = 60
        $this->assertEquals(60, strlen($wrapped));

        $unwrapped = LumenKeyManager::unwrapFileKey($wrapped, $this->masterKey);
        $this->assertEquals($this->fileKey, $unwrapped);
    }

    /**
     * @throws RandomException
     */
    public function testUnwrapFileKeyFailsWithInvalidKey(): void
    {
        $wrapped = LumenKeyManager::wrapFileKey($this->fileKey, $this->masterKey);
        $badMasterKey = LumenKeyManager::generateRandomFileKey(); // just random 32 bytes
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Failed to unwrap file key.');
        LumenKeyManager::unwrapFileKey($wrapped, $badMasterKey);
    }

    /**
     * @throws RandomException
     */
    public function testUnwrapFileKeyFailsOnShortData(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Wrapped key data is too short.');
        LumenKeyManager::unwrapFileKey(random_bytes(10), $this->masterKey);
    }

    /**
     * @throws RandomException
     */
    public function testDeriveChunkIvMatchesLengthAndStructure(): void
    {
        $baseIv = LumenKeyManager::generateBaseIv();
        $this->assertEquals(12, strlen($baseIv));

        $chunkIv = LumenKeyManager::deriveChunkIv($baseIv, 5);
        $this->assertEquals(12, strlen($chunkIv));
        // Only the last 4 bytes are XORed with the chunk index (5)
        $this->assertEquals(substr($baseIv, 0, 8), substr($chunkIv, 0, 8));
    }

    /**
     * @throws RandomException
     */
    public function testEncryptAndDecryptChunkSucceeds(): void
    {
        $iv = LumenKeyManager::generateBaseIv();
        $plaintext = 'hello world segment';

        $cipherBlob = LumenKeyManager::encryptChunk($plaintext, $this->fileKey, $iv, LumenKeyManager::AAD_FILE);
        $this->assertTrue(strlen($cipherBlob) > strlen($plaintext));

        $decrypted = LumenKeyManager::decryptPart($cipherBlob, $this->fileKey, $iv, LumenKeyManager::AAD_FILE);
        $this->assertEquals($plaintext, $decrypted);
    }

    /**
     * @throws RandomException
     */
    public function testDecryptChunkFailsOnTampering(): void
    {
        $iv = LumenKeyManager::generateBaseIv();
        $plaintext = 'hello world segment';
        $cipherBlob = LumenKeyManager::encryptChunk($plaintext, $this->fileKey, $iv, LumenKeyManager::AAD_FILE);

        // Tamper with the ciphertext
        $cipherBlob[0] = $cipherBlob[0] ^ "\x01";

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Decryption/authentication failed.');
        LumenKeyManager::decryptPart($cipherBlob, $this->fileKey, $iv, LumenKeyManager::AAD_FILE);
    }

    /**
     * @throws RandomException
     */
    public function testEncryptAndDecryptMetadataSucceeds(): void
    {
        $filename = 'secret_document.pdf';

        $encryptedB64 = LumenKeyManager::encryptMetadata($filename, $this->fileKey, $this->fileSalt);
        $this->assertNotEquals($filename, $encryptedB64);

        $decrypted = LumenKeyManager::decryptMetadata($encryptedB64, $this->fileKey, $this->fileSalt);
        $this->assertEquals($filename, $decrypted);
    }
}
