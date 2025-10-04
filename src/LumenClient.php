<?php

declare(strict_types=1);

namespace Lumen\Sdk;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Utils;
use JsonException;
use Lumen\Sdk\Response\FileResource;
use Lumen\Sdk\Response\MultipartUploadPart;
use Lumen\Sdk\Response\MultipartUploadResult;
use Lumen\Sdk\Response\MultipartUploadSession;
use Psr\Http\Message\ResponseInterface;
use Random\RandomException;
use RuntimeException;

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
    private const DEFAULT_CHUNK_SIZE = 16_777_216;

    private ClientInterface $httpClient;

    /** @var array<string, string> */
    private array $defaultHeaders;

    private ?Vault $defaultVault = null;

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
        $this->httpClient = $httpClient ?? new GuzzleClient();
        $this->defaultHeaders = array_merge([
            'Accept' => 'application/json',
        ], $defaultHeaders);
    }

    /**
     * Set the default vault for subsequent operations.
     *
     * @param string $slug
     * @return Vault
     */
    public function setVault(string $slug): Vault
    {
        $vault = $this->vaultResolver->resolveBySlug($slug);
        $this->defaultVault = $vault;

        return $vault;
    }

    /**
     * Clear the default vault.
     */
    public function clearVault(): void
    {
        $this->defaultVault = null;
    }

    /**
     * Upload a file to a drive, using simple or multipart upload depending on file size.
     *
     * Automatically selects between simple upload (files <= 16 MiB) and multipart upload
     * (files > 16 MiB) based on the file size. Supports optional client-side encryption.
     *
     * @param string $filePath Path to the local file to be uploaded
     * @param string $driveId Drive ID, optionally with vault slug suffix (e.g. "01jns7j69jfgj3fd5ntsp3sm07-kw2")
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
     * @return FileResource
     *
     * @throws JsonException
     * @throws RandomException
     * @throws GuzzleException
     * @throws RuntimeException
     */
    public function upload(string $filePath, string $driveId, array $options = []): FileResource
    {
        $fileSize = filesize($filePath);
        if ($fileSize === false) {
            throw new RuntimeException(sprintf('Unable to determine size for "%s".', $filePath));
        }

        // When encryption is used, we allow blobs to be DEFAULT_CHUNK_SIZE + GCM_TAG_LEN for each part
        if ($fileSize <= self::DEFAULT_CHUNK_SIZE) {
            return $this->simpleUpload($filePath, $driveId, $options);
        }

        return $this->multipartUpload($filePath, $driveId, $options)->getFile();
    }

    /**
     * Simple upload for small files (up to ~16 MiB).
     *
     * Uploads a file in a single HTTP request. For files larger than 16 MiB,
     * use multipartUpload() or upload() instead. Supports client-side encryption
     * using AES-256-GCM with optional mnemonic-based key derivation.
     *
     * @param string $filePath Path to the local file to be uploaded
     * @param string $driveId Drive ID, optionally with vault slug suffix (e.g. "01jns7j69jfgj3fd5ntsp3sm07-kw2")
     * @param array{
     *     parents?: string[],
     *     created_at?: string,
     *     modified_at?: string,
     *     mime_type?: string,
     *     headers?: array<string, string>,
     *     vault?: string,
     *     encryption?: array<string, mixed>|string
     * } $options
     * @return FileResource
     *
     * @throws JsonException
     * @throws RandomException
     * @throws GuzzleException
     * @throws RuntimeException
     */
    public function simpleUpload(string $filePath, string $driveId, array $options = []): FileResource
    {
        if (!is_file($filePath)) {
            throw new RuntimeException(sprintf('File "%s" does not exist.', $filePath));
        }

        $context = $this->resolveDriveContext($driveId, $options['vault'] ?? null);
        $normalizedDriveId = $context['drive_id'];
        $vault = $context['vault'];

        $encryptionOptions = $options['encryption'] ?? null;

        // If encryption is requested, prepare file salt/key and encrypted blob
        $isEncrypted = false;
        $fileSalt = null;
        $encryptedBlob = null;
        $fileKey = null;

        if ($encryptionOptions !== null && $encryptionOptions !== false) {
            // Resolve master key from provided encryption options. Throws on failure.
            $masterKey = $this->resolveMasterKeyFromEncryptionOptions($encryptionOptions);

            // Generate per-file salt and derive per-file key
            $fileSalt = LumenKeyManager::generateFileSalt();
            $fileKey = LumenKeyManager::deriveFileKey($masterKey, $fileSalt);

            // Read entire file (small file path) and encrypt as a single chunk
            $plaintext = file_get_contents($filePath);
            if ($plaintext === false) {
                throw new RuntimeException(sprintf('Unable to read "%s" for encryption.', $filePath));
            }

            $iv = LumenKeyManager::deriveChunkIv($fileSalt, 0);
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
                'contents' => $normalizedDriveId,
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

        if ($isEncrypted) {
            $encryptedFileName = LumenKeyManager::encryptMetadata($fileName, $fileKey, $fileSalt);
            $multipart[] = ['name' => 'file_name', 'contents' => $encryptedFileName];
            $multipart[] = ['name' => 'file_salt', 'contents' => base64_encode($fileSalt)];
            $multipart[] = ['name' => 'encrypted', 'contents' => '1'];
        }

        try {
            $response = $this->request('POST', $vault, '/v1/files', [
                'headers' => $options['headers'] ?? [],
                'multipart' => $multipart,
            ]);
        } finally {
            if (is_resource($fileStream)) {
                fclose($fileStream);
            }
        }

        /** @noinspection PhpUnhandledExceptionInspection */
        return new FileResource($this->decodeJson($response));
    }

    /**
     * Initialize a new multipart upload session.
     *
     * Creates a session for uploading a large file in multiple parts (chunks).
     * Each part must be uploaded separately using uploadMultipartPart(), then
     * the upload is finalized with completeMultipartUpload().
     *
     * @param string $driveId Drive ID, optionally with vault slug suffix (e.g. "01jns7j69jfgj3fd5ntsp3sm07-kw2")
     * @param string $fileName Name of the file to be created
     * @param int $fileSize Size of the file in bytes
     * @param array{
     *     mime_type?: string,
     *     chunk_size?: int,
     *     file_salt?: string,
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
    public function initializeMultipartUpload(string $driveId, string $fileName, int $fileSize, array $options = []): MultipartUploadSession
    {
        $context = $this->resolveDriveContext($driveId, $options['vault'] ?? null);
        $normalizedDriveId = $context['drive_id'];
        $vault = $context['vault'];

        $payload = array_filter([
            'drive_id' => $normalizedDriveId,
            'file_name' => $fileName,
            'file_size' => $fileSize,
            'mime_type' => $options['mime_type'] ?? null,
            'chunk_size' => $options['chunk_size'] ?? self::DEFAULT_CHUNK_SIZE,
            'file_salt' => $options['file_salt'] ?? null,
            'encrypted' => $options['encrypted'] ?? null,
            'parents' => $options['parents'] ?? null,
            'created_at' => $options['created_at'] ?? null,
            'modified_at' => $options['modified_at'] ?? null,
        ], static fn($value) => $value !== null);

        $response = $this->request('POST', $vault, '/v1/files/multipart-upload/initialize', [
            'headers' => $options['headers'] ?? [],
            'json' => $payload,
        ]);

        $data = $this->decodeJson($response);

        return new MultipartUploadSession(
            id: $data['id'],
            driveId: $data['drive_id'],
            vault: $vault,
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
    public function uploadMultipartPart(
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
     * Use this when an upload fails or needs to be cancelled.
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
     * @param string $driveId Drive ID, optionally with vault slug suffix (e.g. "01jns7j69jfgj3fd5ntsp3sm07-kw2")
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
     */
    public function multipartUpload(string $filePath, string $driveId, array $options = []): MultipartUploadResult
    {
        if (!is_file($filePath)) {
            throw new RuntimeException(sprintf('File "%s" does not exist.', $filePath));
        }

        $fileSize = filesize($filePath);
        if ($fileSize === false) {
            throw new RuntimeException(sprintf('Unable to determine size for "%s".', $filePath));
        }

        $fileName = basename($filePath);
        $chunkSize = $options['chunk_size'] ?? self::DEFAULT_CHUNK_SIZE;
        $mimeType = $options['mime_type'] ?? $this->detectMimeType($filePath);

        $encryptionOptions = $options['encryption'] ?? null;
        $isEncrypted = false;
        $fileSalt = null;
        $fileKey = null;

        if ($encryptionOptions !== null && $encryptionOptions !== false) {
            $masterKey = $this->resolveMasterKeyFromEncryptionOptions($encryptionOptions);
            $fileSalt = LumenKeyManager::generateFileSalt();
            $fileKey = LumenKeyManager::deriveFileKey($masterKey, $fileSalt);
            $isEncrypted = true;
        }

        // When encrypting, each part may be up to GCM_TAG_LEN bytes larger
        if ($isEncrypted) {
            $chunkSize += LumenKeyManager::GCM_TAG_LEN;
            $parts = floor($fileSize / ($chunkSize - LumenKeyManager::GCM_TAG_LEN)) + 1;
            $fileSize += $parts * LumenKeyManager::GCM_TAG_LEN;
            $fileName = LumenKeyManager::encryptMetadata($fileName, $fileKey, $fileSalt);
        }

        $session = $this->initializeMultipartUpload($driveId, $fileName, $fileSize, [
            'mime_type' => $mimeType,
            'chunk_size' => $chunkSize,
            'file_salt' => $fileSalt !== null ? base64_encode($fileSalt) : null,
            'encrypted' => $isEncrypted ? true : null,
            'parents' => $options['parents'] ?? [],
            'created_at' => $options['created_at'] ?? null,
            'modified_at' => $options['modified_at'] ?? null,
            'headers' => $options['headers'] ?? [],
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
                    $iv = LumenKeyManager::deriveChunkIv($fileSalt, $partNumber - 1);
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
                    $options['on_progress']($partNumber, $bytesUploaded - ($isEncrypted ? strlen($blob) : strlen($chunk)), $bytesUploaded, (int)$fileSize);
                }

                ++$partNumber;
            }
        } finally {
            fclose($handle);
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
     * For multi-part files, returns a formatted ETag with part count (e.g., "abc123-3").
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
     * Detect MIME type of a file.
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
     *
     * @param string $driveId
     * @param string|null $preferredVaultSlug
     * @return array{drive_id: string, vault: Vault}
     */
    private function resolveDriveContext(string $driveId, ?string $preferredVaultSlug): array
    {
        [$normalizedDriveId, $embeddedSlug] = $this->extractVaultFromDriveId($driveId);
        $vault = $this->resolveVault($preferredVaultSlug ?? $embeddedSlug);

        return [
            'drive_id' => $normalizedDriveId,
            'vault' => $vault,
        ];
    }

    /**
     * Extract vault slug from drive ID if present.
     *
     * Drive IDs can optionally include a vault slug suffix in the format:
     * {drive_id}-{vault_slug}
     *
     * @param string $driveId
     * @return array{0: string, 1: string|null}
     */
    private function extractVaultFromDriveId(string $driveId): array
    {
        $separator = strrpos($driveId, '-');
        if ($separator === false) {
            return [$driveId, null];
        }

        $maybeVault = substr($driveId, $separator + 1);
        $maybeDrive = substr($driveId, 0, $separator);

        if ($maybeVault === '' || $maybeDrive === '') {
            return [$driveId, null];
        }

        return [$maybeDrive, $maybeVault];
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
            if ($this->defaultVault !== null && strcasecmp($this->defaultVault->slug, $slug) === 0) {
                return $this->defaultVault;
            }

            return $this->vaultResolver->resolveBySlug($slug);
        }

        if ($this->defaultVault !== null) {
            return $this->defaultVault;
        }

        throw new RuntimeException('No vault specified. Call setVault(), pass a vault option, or annotate the drive ID as {id}-{vault}.');
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
    private function resolveMasterKeyFromEncryptionOptions(array|string $enc): string
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
    public function buildNameSearchIndex(string $plainName, string $fileKey): array
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
}
