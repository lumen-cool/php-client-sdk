<?php

declare(strict_types=1);

namespace Lumen\Files;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * PHP client for the Lumen Files upload API.
 */
final class LumenFilesClient
{
    private const DEFAULT_CHUNK_SIZE = 16_777_216; // 16 MiB

    private ClientInterface $httpClient;

    /** @var array<string, string> */
    private array $defaultHeaders;

    public function __construct(string $endpoint, ?ClientInterface $httpClient = null, array $defaultHeaders = [])
    {
        $endpoint = rtrim($endpoint, '/');
        $this->httpClient = $httpClient ?? new GuzzleClient([
            'base_uri' => $endpoint,
        ]);

        $this->defaultHeaders = array_merge([
            'Accept' => 'application/json',
        ], $defaultHeaders);
    }

    /**
     * Performs a simple (single request) upload.
     *
     * @param array{
     *     parents?: string[],
     *     created_at?: string,
     *     modified_at?: string,
     *     mime_type?: string,
     *     etag?: string,
     *     metadata?: array<string, scalar>,
     *     headers?: array<string, string>
     * } $options
     *
     * @return array<string, mixed>
     */
    public function simpleUpload(string $filePath, string $driveId, array $options = []): array
    {
        if (!is_file($filePath)) {
            throw new RuntimeException(sprintf('File "%s" does not exist.', $filePath));
        }

        $fileName = basename($filePath);
        $etag = $options['etag'] ?? md5_file($filePath);
        if ($etag === false) {
            throw new RuntimeException('Unable to calculate MD5 hash for the file.');
        }

        $fileStream = fopen($filePath, 'rb');
        if ($fileStream === false) {
            throw new RuntimeException(sprintf('Unable to open "%s" for reading.', $filePath));
        }

        $multipart = [
            [
                'name' => 'file',
                'contents' => $fileStream,
                'filename' => $fileName,
            ],
            [
                'name' => 'drive_id',
                'contents' => $driveId,
            ],
            [
                'name' => 'etag',
                'contents' => $etag,
            ],
        ];

        if (isset($options['created_at'])) {
            $multipart[] = [
                'name' => 'created_at',
                'contents' => $options['created_at'],
            ];
        }

        if (isset($options['modified_at'])) {
            $multipart[] = [
                'name' => 'modified_at',
                'contents' => $options['modified_at'],
            ];
        }

        if (isset($options['mime_type'])) {
            $multipart[] = [
                'name' => 'mime_type',
                'contents' => $options['mime_type'],
            ];
        }

        if (!empty($options['parents'])) {
            foreach ($options['parents'] as $parent) {
                $multipart[] = [
                    'name' => 'parents[]',
                    'contents' => $parent,
                ];
            }
        }

        if (!empty($options['metadata']) && is_array($options['metadata'])) {
            foreach ($options['metadata'] as $key => $value) {
                if (!is_scalar($value)) {
                    continue;
                }

                $multipart[] = [
                    'name' => (string) $key,
                    'contents' => (string) $value,
                ];
            }
        }

        try {
            $response = $this->httpClient->request('POST', '/v1/files', [
                'headers' => $this->mergeHeaders($options['headers'] ?? []),
                'multipart' => $multipart,
            ]);
        } finally {
            fclose($fileStream);
        }

        return $this->decodeJson($response);
    }

    /**
     * Initializes a multipart upload session.
     *
     * @param string[] $parents
     * @param array<string, string> $headers
     *
     * @return array{id: string, file_name?: string, file_size?: int, mime_type?: string}
     */
    public function initializeMultipartUpload(
        string $driveId,
        string $fileName,
        int $fileSize,
        ?string $mimeType = null,
        int $chunkSize = self::DEFAULT_CHUNK_SIZE,
        array $parents = [],
        ?string $createdAt = null,
        ?string $modifiedAt = null,
        array $headers = []
    ): array {
        $payload = array_filter([
            'drive_id' => $driveId,
            'file_name' => $fileName,
            'file_size' => $fileSize,
            'mime_type' => $mimeType,
            'chunk_size' => $chunkSize,
            'parents' => $parents ?: null,
            'created_at' => $createdAt,
            'modified_at' => $modifiedAt,
        ], static fn ($value) => $value !== null);

        $response = $this->httpClient->request('POST', '/v1/files/multipart-upload/initialize', [
            'headers' => $this->mergeHeaders($headers),
            'json' => $payload,
        ]);

        return $this->decodeJson($response);
    }

    /**
     * Uploads a single multipart chunk.
     *
     * @param array<string, string> $headers
     *
     * @return array<string, mixed>
     */
    public function uploadMultipartPart(
        string $uploadId,
        int $partNumber,
        string $chunkContents,
        ?string $etag = null,
        array $headers = []
    ): array {
        $etag ??= md5($chunkContents);
        if ($etag === false) {
            throw new RuntimeException('Unable to calculate MD5 hash for the provided chunk.');
        }

        $multipart = [
            [
                'name' => 'part_number',
                'contents' => (string) $partNumber,
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

        $response = $this->httpClient->request('POST', sprintf('/v1/files/multipart-upload/%s/parts', $uploadId), [
            'headers' => $this->mergeHeaders($headers),
            'multipart' => $multipart,
        ]);

        return $this->decodeJson($response);
    }

    /**
     * Completes a multipart upload session.
     *
     * @param array<int, array{etag: string, part_number: int}> $parts
     * @param array<string, string> $headers
     *
     * @return array<string, mixed>
     */
    public function completeMultipartUpload(string $uploadId, array $parts, string $overallEtag, array $headers = []): array
    {
        $payload = [
            'parts' => $parts,
            'etag' => $overallEtag,
        ];

        $response = $this->httpClient->request('POST', sprintf('/v1/files/multipart-upload/%s/complete', $uploadId), [
            'headers' => $this->mergeHeaders($headers),
            'json' => $payload,
        ]);

        return $this->decodeJson($response);
    }

    /**
     * Aborts a multipart upload session.
     */
    public function abortMultipartUpload(string $uploadId, array $headers = []): void
    {
        $this->httpClient->request('DELETE', sprintf('/v1/files/multipart-upload/%s/abort', $uploadId), [
            'headers' => $this->mergeHeaders($headers),
        ]);
    }

    /**
     * Performs a full multipart upload workflow for the provided file.
     *
     * @param array{
     *     parents?: string[],
     *     created_at?: string,
     *     modified_at?: string,
     *     mime_type?: string,
     *     chunk_size?: int,
     *     headers?: array<string, string>,
     *     on_progress?: callable(int $partNumber, int $offset, int $bytesUploaded, int $totalBytes): void
     * } $options
     *
     * @return array<string, mixed>
     */
    public function multipartUpload(string $filePath, string $driveId, array $options = []): array
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

        $initResponse = $this->initializeMultipartUpload(
            driveId: $driveId,
            fileName: $fileName,
            fileSize: $fileSize,
            mimeType: $mimeType,
            chunkSize: $chunkSize,
            parents: $options['parents'] ?? [],
            createdAt: $options['created_at'] ?? null,
            modifiedAt: $options['modified_at'] ?? null,
            headers: $options['headers'] ?? []
        );

        $uploadId = $initResponse['id'] ?? null;
        if (!is_string($uploadId) || $uploadId === '') {
            throw new RuntimeException('Upload ID was not returned by the initialization call.');
        }

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

                $partEtag = md5($chunk);
                if ($partEtag === false) {
                    throw new RuntimeException(sprintf('Unable to calculate MD5 hash for part %d.', $partNumber));
                }
                $this->uploadMultipartPart($uploadId, $partNumber, $chunk, $partEtag, $options['headers'] ?? []);

                $parts[] = [
                    'etag' => $partEtag,
                    'part_number' => $partNumber,
                ];

                $bytesUploaded += strlen($chunk);

                if (isset($options['on_progress']) && is_callable($options['on_progress'])) {
                    $options['on_progress']($partNumber, $bytesUploaded - strlen($chunk), $bytesUploaded, $fileSize);
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

        return $this->completeMultipartUpload($uploadId, $parts, $overallEtag, $options['headers'] ?? []);
    }

    /**
     * Calculates the combined ETag for a multipart upload.
     *
     * @param array<int, array{etag: string, part_number: int}> $parts
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

        $final = md5($binary);
        if ($final === false) {
            throw new RuntimeException('Unable to calculate final MD5 hash for multipart upload.');
        }

        return sprintf('%s-%d', $final, count($parts));
    }

    /**
     * @return array<string, string>
     */
    private function mergeHeaders(array $headers): array
    {
        return array_merge($this->defaultHeaders, $headers);
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeJson(ResponseInterface $response): array
    {
        $contents = (string) $response->getBody();

        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);

        return $decoded;
    }

    private function detectMimeType(string $filePath): ?string
    {
        $info = finfo_open(FILEINFO_MIME_TYPE);
        if ($info === false) {
            return null;
        }

        $mimeType = finfo_file($info, $filePath) ?: null;
        finfo_close($info);

        return $mimeType;
    }
}
