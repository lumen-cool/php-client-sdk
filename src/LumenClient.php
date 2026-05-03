<?php
/** @noinspection PhpUnused */

declare(strict_types=1);

namespace Lumen\Sdk;

use Exception;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Utils;
use JsonException;
use Lumen\Sdk\Middleware\UrlSanitizationMiddleware;
use Lumen\Sdk\Response\File;
use Lumen\Sdk\Response\MultipartUploadPart;
use Lumen\Sdk\Response\MultipartUploadResult;
use Lumen\Sdk\Response\MultipartUploadSession;
use Psr\Http\Message\ResponseInterface;
use Random\RandomException;
use RuntimeException;
use SensitiveParameter;
use SodiumException;

/**
 * Client for interacting with the Lumen file storage API.
 *
 * This client provides file upload capabilities with support for:
 * - Simple uploads for small files (up to 16 MiB)
 * - Multipart uploads for large files
 * - Client-side encryption using AES-256-GCM
 * - Vault-based multi-tenant storage
 */
final class LumenClient
{
    /**
     * Default multipart chunk size in bytes (16 MiB).
     */
    public const int DEFAULT_CHUNK_SIZE = 16_777_216;

    private ClientInterface $httpClient;

    /** @var array<string, string> */
    private array $defaultHeaders;

    /**
     * Create a new Lumen client instance.
     *
     * @param VaultResolverInterface $vaultResolver
     * @param ClientInterface|null $httpClient
     * @param array<string, string> $defaultHeaders
     */
    public function __construct(
        private readonly VaultResolverInterface $vaultResolver,
        ?ClientInterface                        $httpClient = null,
        array                                   $defaultHeaders = [],
    )
    {
        if ($httpClient === null) {
            $stack = HandlerStack::create();
            $stack->push(UrlSanitizationMiddleware::create());
            $this->httpClient = new GuzzleClient(['handler' => $stack]);
        } else {
            $this->httpClient = $httpClient;
        }

        $this->defaultHeaders = array_merge([
            'Accept' => 'application/json',
        ], $defaultHeaders);
    }

    /**
     * Upload a file to a drive, using simple or multipart upload depending on file size.
     *
     * Automatically selects between simple upload (files <= 16 MiB) and multipart upload
     * (files > 16 MiB) based on the file size. Supports optional client-side encryption.
     *
     * @param string $filePath Path to the local file to be uploaded
     * @param string $federatedId Federated Drive ID
     * @param array{
     *     parents?: string[],
     *     created_at?: string,
     *     modified_at?: string,
     *     mime_type?: string,
     *     etag?: string,
     *     chunk_size?: int,
     *     headers?: array<string, string>,
     *     on_progress?: callable(int $partNumber, int $offset, int $bytesUploaded, int $totalBytes): void,
     *     vault?: string,
     *     encryption?: array<string, mixed>|string
     * } $options
     * @return File
     *
     * @throws GuzzleException
     * @throws JsonException
     * @throws RandomException
     * @throws SodiumException
     */
    public function upload(string $filePath, string $federatedId, array $options = []): File
    {
        $fileSize = filesize($filePath);
        if ($fileSize === false) {
            throw new RuntimeException(sprintf('Unable to determine size for "%s".', $filePath));
        }

        // When encryption is used, we allow blobs to be DEFAULT_CHUNK_SIZE + GCM_TAG_LEN for each part
        if ($fileSize <= self::DEFAULT_CHUNK_SIZE) {
            return $this->simpleUpload($filePath, $federatedId, $options);
        }

        return $this->multipartUpload($filePath, $federatedId, $options)->getFile();
    }

    /**
     * Download a file from a vault.
     * Supports both downloading with a master key (Mode A) and with a shareable raw file key (Mode B).
     *
     * @param string $federatedId The ID of the file to download
     * @param string $destinationPath Path to save the downloaded file
     * @param array{
     *     vault?: string,
     *     encryption?: array<string, mixed>|string,
     *     raw_file_key?: string,
     *     headers?: array<string, string>
     * } $options
     * @return void
     *
     * @throws JsonException
     * @throws GuzzleException
     * @throws RuntimeException
     * @throws SodiumException
     */
    public function download(string $federatedId, string $destinationPath, array $options = []): void
    {
        $file = $this->retrieve($federatedId, $options);

        // 2. Fetch the file content
        $contentResponse = $this->httpClient->request('GET', $file->getDownloadUrl(), [
            'headers' => $options['headers'] ?? [],
            'stream' => true,
        ]);
        $contentStream = $contentResponse->getBody();

        if (!$file->getEncryption()) {
            // Unencrypted file, stream directly to disk
            $dest = Utils::streamFor(fopen($destinationPath, 'wb'));
            Utils::copyToStream($contentStream, $dest);
            return;
        }

        // Handle Encrypted File
        $encryption = $file->getEncryption();
        $baseIv = $encryption->getBaseIV() ? base64_decode($encryption->getBaseIV(), true) : null;
        if ($baseIv === false || $baseIv === null) {
            throw new RuntimeException("Missing or invalid base_iv in file metadata.");
        }

        // Mode B: Public Share Link (Raw Key provided)
        if (isset($options['raw_file_key'])) {
            $fileKey = $options['raw_file_key'];

            // If the user passed the Base64URL fragment directly, decode it safely
            if (strlen($fileKey) > 32) {
                $fileKey = base64_decode(strtr($fileKey, '-_', '+/'));
            }

            if (strlen($fileKey) !== 32) {
                throw new RuntimeException("Invalid raw_file_key length. Expected 32 bytes.");
            }
        } // Mode A: Authenticated Owner (Master Key unwraps wrapped_key)
        else if (isset($options['encryption'])) {
            $masterKey = $this->resolveMasterKeyFromEncryptionOptions($options['encryption']);
            $wrappedKey = $encryption->getWrappedKey() ? base64_decode($encryption->getWrappedKey(), true) : null;
            if ($wrappedKey === false || $wrappedKey === null) {
                throw new RuntimeException("Missing or invalid wrapped_key in file metadata.");
            }
            $fileKey = LumenKeyManager::unwrapFileKey($wrappedKey, $masterKey);
        } else {
            throw new RuntimeException("Cannot decrypt file: Neither raw_file_key nor encryption master_key provided.");
        }

        // Decrypt the stream to destination
        $outStream = fopen($destinationPath, 'wb');
        if ($outStream === false) {
            throw new RuntimeException("Cannot open destination path for writing: $destinationPath");
        }

        $serverChunkSize = $encryption->getChunkSize() ?? $file->getSize();
        $chunkSize = $serverChunkSize + LumenKeyManager::GCM_TAG_LEN;

        try {
            $partNumber = 0;
            while (!$contentStream->eof()) {
                $blob = '';
                // Efficiently read until chunk size is met or EOF reached
                while (strlen($blob) < $chunkSize && !$contentStream->eof()) {
                    $read = $contentStream->read($chunkSize - strlen($blob));
                    if ($read === '') {
                        break;
                    }
                    $blob .= $read;
                }

                if ($blob === '') {
                    break;
                }

                // Decrypt
                try {
                    $iv = LumenKeyManager::deriveChunkIv($baseIv, $partNumber);
                    $pt = LumenKeyManager::decryptPart($blob, $fileKey, $iv, LumenKeyManager::AAD_FILE);
                } catch (Exception $e) {
                    throw new RuntimeException("Decryption failed at part {$partNumber}: " . $e->getMessage());
                }

                // Write
                if (fwrite($outStream, $pt) === false) {
                    throw new RuntimeException("Failed to write decrypted data to output stream.");
                }

                $partNumber++;
            }
        } catch (RuntimeException $e) {
            // On failure, delete the incomplete file if it was created
            if (file_exists($destinationPath)) {
                unlink($destinationPath);
            }
            throw $e;
        } finally {
            if (is_resource($outStream)) {
                fclose($outStream);
            }
            if (function_exists('sodium_memzero')) {
                sodium_memzero($fileKey);
            }
        }
    }

    /**
     * Simple upload for small files (up to ~16 MiB).
     *
     * Uploads a file in a single HTTP request. For files larger than 16 MiB,
     * use multipartUpload() or upload() instead. Supports client-side encryption
     * using AES-256-GCM with optional mnemonic-based key derivation.
     *
     * @param string $filePath Path to the local file to be uploaded
     * @param FederatedId|string $federatedId Drive ID
     * @param array{
     *     parents?: string[],
     *     created_at?: string,
     *     modified_at?: string,
     *     mime_type?: string,
     *     headers?: array<string, string>,
     *     vault?: string,
     *     encryption?: array<string, mixed>|string
     * } $options
     * @return File
     *
     * @throws JsonException
     * @throws RandomException
     * @throws GuzzleException
     * @throws RuntimeException
     * @throws SodiumException
     */
    public function simpleUpload(string $filePath, FederatedId|string $federatedId, array $options = []): File
    {
        if (!is_file($filePath)) {
            throw new RuntimeException(sprintf('File "%s" does not exist.', $filePath));
        }

        $context = $this->resolveContext($federatedId, $options['vault'] ?? null);
        $encryptionOptions = $options['encryption'] ?? null;

        // If encryption is requested, prepare file salt/key and encrypted blob
        $isEncrypted = false;
        $encryptedBlob = null;
        $fileKey = null;
        $wrappedKey = null;
        $baseIv = null;

        if ($encryptionOptions !== null && $encryptionOptions !== false) {
            // Resolve master key from provided encryption options. Throws on failure.
            $masterKey = $this->resolveMasterKeyFromEncryptionOptions($encryptionOptions);

            // Generate a new purely random file key
            $fileKey = LumenKeyManager::generateRandomFileKey();

            // Wrap the file key with the user's master key for backend storage
            $wrappedKey = LumenKeyManager::wrapFileKey($fileKey, $masterKey);

            // Generate deterministic base IV for the session
            $baseIv = LumenKeyManager::generateBaseIv();

            // Read entire file (small file path) and encrypt as a single chunk
            $plaintext = file_get_contents($filePath);
            if ($plaintext === false) {
                throw new RuntimeException(sprintf('Unable to read "%s" for encryption.', $filePath));
            }

            $iv = LumenKeyManager::deriveChunkIv($baseIv, 0);
            $encryptedBlob = LumenKeyManager::encryptChunk($plaintext, $fileKey, $iv, LumenKeyManager::AAD_FILE);

            $fileStream = Utils::streamFor($encryptedBlob);
            $isEncrypted = true;
        } else {
            $fileStream = fopen($filePath, 'rb');
            if ($fileStream === false) {
                throw new RuntimeException(sprintf('Unable to open "%s" for reading.', $filePath));
            }
        }

        if ($isEncrypted) {
            $etag = md5($encryptedBlob);
        } else {
            $etag = md5_file($filePath);
            if ($etag === false) {
                if (is_resource($fileStream)) fclose($fileStream);
                throw new RuntimeException('Unable to calculate MD5 hash for the file.');
            }
        }

        $fileName = basename($filePath);

        $multipart = [
            [
                'name' => 'file',
                'contents' => $fileStream,
                // when filename is sensitive (encrypted payload) avoid leaking it in the multipart filename header
                'filename' => $isEncrypted ? 'encrypted' : $fileName,
            ],
            [
                'name' => 'drive_id',
                'contents' => $context->getId(),
            ],
            [
                'name' => 'etag',
                'contents' => $etag,
            ],
        ];

        if (isset($options['created_at'])) {
            $multipart[] = ['name' => 'created_at', 'contents' => $options['created_at']];
        }

        if (isset($options['modified_at'])) {
            $multipart[] = ['name' => 'modified_at', 'contents' => $options['modified_at']];
        }

        if (isset($options['mime_type'])) {
            $multipart[] = ['name' => 'mime_type', 'contents' => $options['mime_type']];
        }

        if (!empty($options['parents'])) {
            foreach ($options['parents'] as $parent) {
                $multipart[] = ['name' => 'parents[]', 'contents' => $parent];
            }
        }

        $requestHeaders = $options['headers'] ?? [];

        if ($isEncrypted) {
            $requestHeaders['x-lumen-ce-v'] = '2';
            $requestHeaders['x-lumen-ce-alg'] = 'A256GCM';
            $requestHeaders['x-lumen-ce-base-iv'] = base64_encode($baseIv);
            $requestHeaders['x-lumen-ce-wrapped-key'] = base64_encode($wrappedKey);
            $requestHeaders['x-lumen-ce-chunk'] = (string)filesize($filePath);

            $encryptedFileName = LumenKeyManager::encryptMetadata($fileName, $fileKey, $baseIv);
            $multipart[] = ['name' => 'file_name', 'contents' => $encryptedFileName];
        }

        try {
            $response = $this->request('POST', $context->getVault(), '/v1/files', [
                'headers' => $requestHeaders,
                'multipart' => $multipart,
            ]);
        } finally {
            if (is_resource($fileStream)) {
                fclose($fileStream);
            }
            if (function_exists('sodium_memzero') && $fileKey !== null) {
                sodium_memzero($fileKey);
            }
        }

        /** @noinspection PhpUnhandledExceptionInspection */
        return new File($this->decodeJson($response));
    }

    /**
     * Initialize a new multipart upload session.
     *
     * Creates a session for uploading a large file in multiple parts (chunks).
     * Each part must be uploaded separately using uploadMultipartPart(), then
     * the upload is finalized with completeMultipartUpload().
     *
     * @param FederatedId|string $federatedId Federated Drive ID
     * @param string $fileName Name of the file to be created
     * @param int $fileSize Size of the file in bytes
     * @param array{
     *     mime_type?: string,
     *     chunk_size?: int,
     *     base_iv?: string,
     *     wrapped_key?: string,
     *     encrypted?: bool,
     *     parents?: string[],
     *     created_at?: string,
     *     modified_at?: string,
     *     headers?: array<string, string>,
     *     vault?: string
     * } $options
     * @return MultipartUploadSession
     *
     * @throws JsonException
     * @throws GuzzleException
     */
    public function initializeMultipartUpload(FederatedId|string $federatedId, string $fileName, int $fileSize, array $options = []): MultipartUploadSession
    {
        $context = $this->resolveContext($federatedId, $options['vault'] ?? null);

        $payload = array_filter([
            'drive_id' => $context->getId(),
            'file_name' => $fileName,
            'file_size' => $fileSize,
            'mime_type' => $options['mime_type'] ?? null,
            'chunk_size' => $options['chunk_size'] ?? self::DEFAULT_CHUNK_SIZE,
            'base_iv' => $options['base_iv'] ?? null,
            'wrapped_key' => $options['wrapped_key'] ?? null,
            'encrypted' => $options['encrypted'] ?? null,
            'parents' => $options['parents'] ?? null,
            'created_at' => $options['created_at'] ?? null,
            'modified_at' => $options['modified_at'] ?? null,
        ], static fn($value) => $value !== null);

        $response = $this->request('POST', $context->getVault(), '/v1/files/multipart-upload/initialize', [
            'headers' => $options['headers'] ?? [],
            'json' => $payload,
        ]);

        $data = $this->decodeJson($response);

        return new MultipartUploadSession(
            id: $data['session']['id'],
            driveId: $data['file_preview']['drive_id'],
            vault: $context->getVault(),
            attributes: $data,
        );
    }

    /**
     * Upload a single part (chunk) to an existing multipart upload session.
     *
     * Uploads one chunk of a file as part of a multipart upload. Parts are numbered
     * sequentially starting from 1. Each part must include an ETag (MD5 hash) for
     * verification.
     *
     * @param MultipartUploadSession|string $sessionOrSessionId Session object or session ID
     * @param int $partNumber Part number (1-based)
     * @param string $chunkContents Contents of the chunk to be uploaded
     * @param string $etag ETag (MD5 hash) of the chunk (without quotes)
     * @param array{
     *     headers?: array<string, string>,
     *     vault?: string
     * } $options
     * @return MultipartUploadPart
     *
     * @throws JsonException
     * @throws GuzzleException
     * @throws RuntimeException
     */
    private function uploadMultipartPart(
        MultipartUploadSession|string $sessionOrSessionId,
        int                           $partNumber,
        string                        $chunkContents,
        string                        $etag,
        array                         $options = []
    ): MultipartUploadPart
    {
        $headers = $options['headers'] ?? [];
        $vault = $sessionOrSessionId instanceof MultipartUploadSession ? $sessionOrSessionId->getVault() : null;
        $sessionId = $sessionOrSessionId instanceof MultipartUploadSession ? $sessionOrSessionId->getId() : $sessionOrSessionId;

        $vault = $this->resolveVault($options['vault'] ?? null, $vault);

        $multipart = [
            [
                'name' => 'part_number',
                'contents' => (string)$partNumber,
            ],
            [
                'name' => 'file',
                'contents' => Utils::streamFor($chunkContents),
                'filename' => sprintf('part-%d', $partNumber),
            ],
            [
                'name' => 'etag',
                'contents' => $etag,
            ],
        ];

        $response = $this->request('POST', $vault, sprintf('/v1/files/multipart-upload/%s/parts', $sessionId), [
            'headers' => $headers,
            'multipart' => $multipart,
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new RuntimeException('Failed to upload part ' . $partNumber . ' of session ' . $sessionId . '. Status code: ' . $response->getStatusCode());
        }

        $data = $this->decodeJson($response);

        return new MultipartUploadPart(
            partNumber: $data['part_number'] ?? $partNumber,
            etag: $data['etag'],
            attributes: $data,
        );
    }

    /**
     * Complete a multipart upload session.
     *
     * Finalizes a multipart upload by providing information about all uploaded parts
     * and the overall ETag. After completion, the file becomes available in the drive.
     *
     * @param MultipartUploadSession|string $sessionOrSessionId Session object or session ID
     * @param array<int, array{etag: string, part_number: int}> $parts
     * @param string $overallEtag Overall ETag for the complete file (MD5 or MD5-N)
     * @param array{
     *     headers?: array<string, string>,
     *     vault?: string
     * } $options
     * @return MultipartUploadResult
     *
     * @throws JsonException
     * @throws GuzzleException
     */
    public function completeMultipartUpload(
        MultipartUploadSession|string $sessionOrSessionId,
        array                         $parts,
        string                        $overallEtag,
        array                         $options = []
    ): MultipartUploadResult
    {
        $headers = $options['headers'] ?? [];
        $vault = $sessionOrSessionId instanceof MultipartUploadSession ? $sessionOrSessionId->getVault() : null;
        $sessionId = $sessionOrSessionId instanceof MultipartUploadSession ? $sessionOrSessionId->getId() : $sessionOrSessionId;

        $vault = $this->resolveVault($options['vault'] ?? null, $vault);

        $payload = [
            'parts' => $parts,
            'etag' => $overallEtag,
        ];

        $response = $this->request('POST', $vault, sprintf('/v1/files/multipart-upload/%s/complete', $sessionId), [
            'headers' => $headers,
            'json' => $payload,
        ]);

        return new MultipartUploadResult($this->decodeJson($response));
    }

    /**
     * Abort a multipart upload session.
     *
     * Cancels an in-progress multipart upload and discards all uploaded parts.
     * Use this when an upload fails or needs to be canceled.
     *
     * @param MultipartUploadSession|string $sessionOrSessionId Session object or session ID
     * @param array{
     *     headers?: array<string, string>,
     *     vault?: string
     * } $options
     *
     * @throws GuzzleException
     */
    public function abortMultipartUpload(MultipartUploadSession|string $sessionOrSessionId, array $options = []): void
    {
        $headers = $options['headers'] ?? [];
        $vault = $sessionOrSessionId instanceof MultipartUploadSession ? $sessionOrSessionId->getVault() : null;
        $sessionId = $sessionOrSessionId instanceof MultipartUploadSession ? $sessionOrSessionId->getId() : $sessionOrSessionId;

        $vault = $this->resolveVault($options['vault'] ?? null, $vault);

        $this->request('DELETE', $vault, sprintf('/v1/files/multipart-upload/%s/abort', $sessionId), [
            'headers' => $headers,
        ]);
    }

    /**
     * Upload a file using multipart upload.
     *
     * Handles the entire multipart upload process: initializes the session, uploads
     * all parts sequentially, and completes the upload. Supports client-side encryption
     * and progress callbacks.
     *
     * @param string $filePath Path to the local file to be uploaded
     * @param string $federatedId Federated Drive ID
     * @param array{
     *     parents?: string[],
     *     created_at?: string,
     *     modified_at?: string,
     *     mime_type?: string,
     *     chunk_size?: int,
     *     headers?: array<string, string>,
     *     on_progress?: callable(int $partNumber, int $offset, int $bytesUploaded, int $totalBytes): void,
     *     vault?: string,
     *     encryption?: array<string, mixed>|string,
     * } $options
     * @return MultipartUploadResult
     *
     * @throws RandomException
     * @throws JsonException
     * @throws GuzzleException
     * @throws RuntimeException
     * @throws SodiumException
     */
    public function multipartUpload(string $filePath, string $federatedId, array $options = []): MultipartUploadResult
    {
        if (!is_file($filePath)) {
            throw new RuntimeException(sprintf('File "%s" does not exist.', $filePath));
        }

        $realFileSize = filesize($filePath);
        if ($realFileSize === false) {
            throw new RuntimeException(sprintf('Unable to determine size for "%s".', $filePath));
        }

        $fileName = basename($filePath);
        $chunkSize = $options['chunk_size'] ?? self::DEFAULT_CHUNK_SIZE;
        $mimeType = $options['mime_type'] ?? $this->detectMimeType($filePath);

        $encryptionOptions = $options['encryption'] ?? null;
        $isEncrypted = false;
        $baseIv = null;
        $wrappedKey = null;
        $fileKey = null;

        if ($encryptionOptions !== null && $encryptionOptions !== false) {
            $masterKey = $this->resolveMasterKeyFromEncryptionOptions($encryptionOptions);

            $fileKey = LumenKeyManager::generateRandomFileKey();
            $wrappedKey = LumenKeyManager::wrapFileKey($fileKey, $masterKey);
            $baseIv = LumenKeyManager::generateBaseIv();

            $isEncrypted = true;
        }

        $requestHeaders = $options['headers'] ?? [];

        // When encrypting, each part may be up to GCM_TAG_LEN bytes larger
        if ($isEncrypted) {
            $requestHeaders['x-lumen-ce-v'] = '2';
            $requestHeaders['x-lumen-ce-alg'] = 'A256GCM';
            $requestHeaders['x-lumen-ce-base-iv'] = base64_encode($baseIv);
            $requestHeaders['x-lumen-ce-wrapped-key'] = base64_encode($wrappedKey);
            $requestHeaders['x-lumen-ce-chunk'] = (string)$chunkSize;

            $fileName = LumenKeyManager::encryptMetadata($fileName, $fileKey, $baseIv);
        }

        $session = $this->initializeMultipartUpload($federatedId, $fileName, $realFileSize, [
            'mime_type' => $mimeType,
            'chunk_size' => $chunkSize,
            'base_iv' => $baseIv !== null ? base64_encode($baseIv) : null,
            'wrapped_key' => $wrappedKey !== null ? base64_encode($wrappedKey) : null,
            'encrypted' => $isEncrypted ? true : null,
            'parents' => $options['parents'] ?? [],
            'created_at' => $options['created_at'] ?? null,
            'modified_at' => $options['modified_at'] ?? null,
            'headers' => $requestHeaders,
            'vault' => $options['vault'] ?? null,
        ]);

        $handle = fopen($filePath, 'rb');
        if ($handle === false) {
            throw new RuntimeException(sprintf('Unable to open "%s" for reading.', $filePath));
        }

        $parts = [];
        $partNumber = 1;
        $bytesUploaded = 0;

        try {
            while (!feof($handle)) {
                $chunk = fread($handle, $chunkSize);
                if ($chunk === false) {
                    throw new RuntimeException('Failed to read file chunk.');
                }

                if ($chunk === '' && feof($handle)) {
                    break;
                }

                if ($isEncrypted) {
                    // derive IV for this part (LumenKeyManager expects 0-based index)
                    $iv = LumenKeyManager::deriveChunkIv($baseIv, $partNumber - 1);
                    $blob = LumenKeyManager::encryptChunk($chunk, $fileKey, $iv, LumenKeyManager::AAD_FILE);
                    $partEtag = md5($blob);

                    $partResponse = $this->uploadMultipartPart($session, $partNumber, $blob, $partEtag, [
                        'headers' => $options['headers'] ?? [],
                    ]);
                } else {
                    if (!$partEtag = md5($chunk)) {
                        throw new RuntimeException(sprintf('Unable to calculate MD5 hash for part %d.', $partNumber));
                    }

                    $partResponse = $this->uploadMultipartPart($session, $partNumber, $chunk, $partEtag, [
                        'headers' => $options['headers'] ?? [],
                    ]);
                }

                $parts[] = [
                    'etag' => $partResponse->getEtagWithoutQuotes(),
                    'part_number' => $partResponse->getPartNumber(),
                ];

                $bytesUploaded += ($isEncrypted ? strlen($blob) : strlen($chunk));

                if (isset($options['on_progress']) && is_callable($options['on_progress'])) {
                    $options['on_progress']($partNumber, $bytesUploaded - ($isEncrypted ? strlen($blob) : strlen($chunk)), $bytesUploaded, $realFileSize);
                }

                ++$partNumber;
            }
        } finally {
            fclose($handle);
            if (function_exists('sodium_memzero') && $fileKey !== null) {
                sodium_memzero($fileKey);
            }
        }

        if ($parts === []) {
            throw new RuntimeException('No file data was read; aborting multipart upload.');
        }

        $overallEtag = $this->calculateMultipartEtag($parts);

        return $this->completeMultipartUpload($session, $parts, $overallEtag, [
            'headers' => $options['headers'] ?? [],
        ]);
    }

    /**
     * Calculate the overall ETag for a multipart upload.
     *
     * Computes the composite ETag by hashing the concatenated binary MD5 values
     * of all parts. For single-part files, returns the part's ETag directly.
     * For multipart files, returns a formatted ETag with part count (e.g., "abc123-3").
     *
     * @param array<int, array{etag: string, part_number: int}> $parts
     * @return string
     *
     * @throws RuntimeException
     */
    public function calculateMultipartEtag(array $parts): string
    {
        if ($parts === []) {
            throw new RuntimeException('Cannot calculate ETag without any parts.');
        }

        if (count($parts) === 1) {
            return $parts[0]['etag'];
        }

        $binary = '';
        foreach ($parts as $part) {
            $chunk = hex2bin($part['etag']);
            if ($chunk === false) {
                throw new RuntimeException(sprintf('Invalid ETag value "%s" provided for part %d.', $part['etag'], $part['part_number']));
            }

            $binary .= $chunk;
        }

        if (!$final = md5($binary)) {
            throw new RuntimeException('Unable to calculate final MD5 hash for multipart upload.');
        }

        return sprintf('%s-%d', $final, count($parts));
    }

    /**
     * Merge default headers with request-specific headers.
     *
     * @param array<string, string> $headers
     * @return array<string, string>
     */
    private function mergeHeaders(array $headers): array
    {
        return array_merge($this->defaultHeaders, $headers);
    }

    /**
     * Send an HTTP request to the vault endpoint.
     *
     * @param string $method
     * @param Vault $vault
     * @param string $uri
     * @param array<string, mixed> $options
     * @return ResponseInterface
     *
     * @throws GuzzleException
     */
    private function request(string $method, Vault $vault, string $uri, array $options): ResponseInterface
    {
        $options['headers'] = $this->mergeHeaders($options['headers'] ?? []);
        $url = rtrim($vault->endpoint, '/') . '/' . ltrim($uri, '/');

        return $this->httpClient->request($method, $url, $options);
    }

    /**
     * Decode JSON response body.
     *
     * @param ResponseInterface $response
     * @return array<string, mixed>
     *
     * @throws JsonException
     */
    private function decodeJson(ResponseInterface $response): array
    {
        $contents = (string)$response->getBody();

        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);

        return $decoded;
    }

    /**
     * Detect MIME type of file.
     *
     * @param string $filePath
     * @return string|null
     */
    private function detectMimeType(string $filePath): ?string
    {
        $info = finfo_open(FILEINFO_MIME_TYPE);
        if ($info === false) {
            return null;
        }

        $mimeType = finfo_file($info, $filePath) ?: null;
        finfo_close($info);

        return $mimeType === false ? null : $mimeType;
    }

    /**
     * Resolve drive ID and vault from drive context.
     */
    private function resolveContext(FederatedId|string $federatedId, ?string $preferredVaultSlug): Context
    {
        $federatedId = FederatedId::parse($federatedId);
        $vault = $this->resolveVault($preferredVaultSlug ?? $federatedId->getSlug());

        return new Context(id: $federatedId->getId(), vault: $vault);
    }

    /**
     * Resolve a vault from slug or fallback options.
     *
     * @param string|null $slug
     * @param Vault|null $fallback
     * @return Vault
     *
     * @throws RuntimeException
     */
    private function resolveVault(?string $slug, ?Vault $fallback = null): Vault
    {
        if ($fallback !== null) {
            return $fallback;
        }

        if ($slug !== null) {
            return $this->vaultResolver->resolveBySlug($slug);
        }

        throw new RuntimeException('No vault specified. Pass a vault option, or annotate the ID as {id}-{vault}.');
    }

    /**
     * Resolve the master key from encryption options.
     *
     * Supported forms:
     * - string (raw master key or hex encoded 64-char)
     * - ['master_key' => string] same as above
     * - ['mnemonic' => string, 'passphrase' => string?]
     *
     * If a hex master key is provided it will be hex-decoded.
     *
     * @param array<string,mixed>|string $enc
     * @return string  Raw 32-byte master key
     *
     * @throws RuntimeException
     */
    private function resolveMasterKeyFromEncryptionOptions(#[SensitiveParameter] array|string $enc): string
    {
        if (is_string($enc) && $enc !== '') {
            // If hex
            if (ctype_xdigit($enc) && strlen($enc) === 64) {
                $decoded = hex2bin($enc);
                if ($decoded === false) throw new RuntimeException('Invalid hex master key.');
                return $decoded;
            }

            // raw binary assumed (length 32 expected)
            if (strlen($enc) === 32) return $enc;

            throw new RuntimeException('Unsupported master key format; provide raw 32-byte key or 64-char hex.');
        }

        if (is_array($enc)) {
            if (isset($enc['master_key'])) {
                $mk = $enc['master_key'];
                if (!is_string($mk) || $mk === '') {
                    throw new RuntimeException('master_key must be a non-empty string.');
                }
                if (ctype_xdigit($mk) && strlen($mk) === 64) {
                    $decoded = hex2bin($mk);
                    if ($decoded === false) throw new RuntimeException('Invalid hex master key.');
                    return $decoded;
                }
                if (strlen($mk) === 32) return $mk;

                throw new RuntimeException('Unsupported master_key format; provide raw 32-byte key or 64-char hex.');
            }

            if (isset($enc['mnemonic'])) {
                $mnemonic = $enc['mnemonic'];
                $pass = isset($enc['passphrase']) ? (string)$enc['passphrase'] : '';
                if (!is_string($mnemonic) || $mnemonic === '') throw new RuntimeException('mnemonic must be a non-empty string.');
                return LumenKeyManager::deriveMasterKeyFromMnemonic($mnemonic, $pass);
            }
        }

        throw new RuntimeException('Unsupported encryption option provided. Provide master_key (raw or hex) or mnemonic.');
    }

    /**
     * Build a search index for encrypted file names.
     *
     * Creates searchable tokens from the plain file name using HMAC-SHA256.
     * Includes the full normalized name and individual tokens for partial matching.
     * Tokens are truncated to 16 bytes (32 hex characters) for efficient storage.
     *
     * @param string $plainName Plain text file name
     * @param string $fileKey Per-file encryption key (32 bytes)
     * @return array<int, string>  Array of searchable token hashes
     */
    public function buildNameSearchIndex(string $plainName, #[SensitiveParameter] string $fileKey): array
    {
        // Derive a subkey for indexing (32 bytes)
        $indexKey = hash_hkdf('sha256', $fileKey, 32, 'lumen-name-index');

        // Normalize
        $normalized = mb_strtolower(trim($plainName));
        // Basic tokenization (split on non-alnum)
        $tokens = preg_split('/[^a-z0-9]+/u', $normalized, -1, PREG_SPLIT_NO_EMPTY) ?: [];

        // Always include the full normalized name for exact search
        $unique = array_values(array_unique(array_merge([$normalized], $tokens)));

        $index = [];
        foreach ($unique as $t) {
            // HMAC then truncate (e.g. 16 bytes -> 32 hex chars)
            $h = hash_hmac('sha256', $t, $indexKey, true);
            $index[] = bin2hex(substr($h, 0, 16));
        }

        return $index;
    }

    /**
     * Generates a shareable link containing the raw file decryption key in the URL fragment.
     * The file key is encoded safely using Base64URL encoding so it does not interfere with the URL structure.
     *
     * @param File $file The unique identifier of the file to be shared including vault slug (e.g. "abc123-kw2").
     * @param string|null $baseUrl The base URL of the application or viewing endpoint.
     * @return ShareableLink The formatted URL with the key securely in the fragment.
     */
    public function generateShareableLink(File $file, #[SensitiveParameter] string|null $masterKey, string|null $baseUrl = null): ShareableLink
    {
        $base64UrlKey = null;
        if ($file->getEncryption() && $file->getEncryption()->getWrappedKey() && $masterKey) {
            $base64UrlKey = rtrim(strtr(base64_encode(
                string: LumenKeyManager::unwrapFileKey(
                    wrappedKeyData: base64_decode(
                        string: $file->getEncryption()->getWrappedKey(),
                        strict: true,
                    ),
                    masterKey: $masterKey
                )
            ), '+/', '-_'), '=');
        }

        $baseUrl = rtrim($baseUrl ?? ShareableLink::baseUrl(), '/');

        return new ShareableLink(
            url: sprintf('%s/files/%s/view', $baseUrl, $file->getFederatedId()),
            encodedKey: $base64UrlKey
        );
    }

    /**
     * Retrieve file metadata and details.
     *
     * @throws GuzzleException
     * @throws JsonException
     */
    public function retrieve(FederatedId|string $federatedId, array $options = []): File
    {
        $context = $this->resolveContext($federatedId, $options['vault'] ?? null);

        $response = $this->request('GET', $context->getVault(), sprintf('/v1/files/%s', $context->getId()), [
            'headers' => $options['headers'] ?? [],
        ]);
        $metadata = $this->decodeJson($response);

        return new File($metadata);
    }
}
