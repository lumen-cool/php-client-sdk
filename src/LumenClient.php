<?php

declare(strict_types=1);

namespace Lumen\Sdk;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Utils;
use Lumen\Sdk\Response\FileResource;
use Lumen\Sdk\Response\MultipartUploadPart;
use Lumen\Sdk\Response\MultipartUploadResult;
use Lumen\Sdk\Response\MultipartUploadSession;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

final class LumenClient
{
    private const DEFAULT_CHUNK_SIZE = 16_777_216; // 16 MiB

    private ClientInterface $httpClient;

    /** @var array<string, string> */
    private array $defaultHeaders;

    private ?Vault $defaultVault = null;

    public function __construct(
        private VaultResolverInterface $vaultResolver,
        ?ClientInterface               $httpClient = null,
        array                          $defaultHeaders = [],
    )
    {
        $this->httpClient = $httpClient ?? new GuzzleClient();
        $this->defaultHeaders = array_merge([
            'Accept' => 'application/json',
        ], $defaultHeaders);
    }

    public function setVault(string $slug): Vault
    {
        $vault = $this->vaultResolver->resolveBySlug($slug);
        $this->defaultVault = $vault;

        return $vault;
    }

    public function clearVault(): void
    {
        $this->defaultVault = null;
    }

    /**
     * @param array{
     *     parents?: string[],
     *     created_at?: string,
     *     modified_at?: string,
     *     mime_type?: string,
     *     etag?: string,
     *     chunk_size?: int,
     *     headers?: array<string, string>,
     *     on_progress?: callable(int $partNumber, int $offset, int $bytesUploaded, int $totalBytes): void,
     *     vault?: string
     * } $options
     */
    public function upload(string $filePath, string $driveId, array $options = []): FileResource
    {
        $fileSize = filesize($filePath);
        if ($fileSize === false) {
            throw new RuntimeException(sprintf('Unable to determine size for "%s".', $filePath));
        }

        if ($fileSize <= self::DEFAULT_CHUNK_SIZE) {
            return $this->simpleUpload($filePath, $driveId, $options);
        }

        return $this->multipartUpload($filePath, $driveId, $options)->getFile();
    }

    /**
     * @param array{
     *     parents?: string[],
     *     created_at?: string,
     *     modified_at?: string,
     *     mime_type?: string,
     *     etag?: string,
     *     metadata?: array<string, scalar>,
     *     headers?: array<string, string>,
     *     vault?: string
     * } $options
     */
    public function simpleUpload(string $filePath, string $driveId, array $options = []): FileResource
    {
        if (!is_file($filePath)) {
            throw new RuntimeException(sprintf('File "%s" does not exist.', $filePath));
        }

        $context = $this->resolveDriveContext($driveId, $options['vault'] ?? null);
        $normalizedDriveId = $context['drive_id'];
        $vault = $context['vault'];

        $fileStream = fopen($filePath, 'rb');
        if ($fileStream === false) {
            throw new RuntimeException(sprintf('Unable to open "%s" for reading.', $filePath));
        }

        $etag = $options['etag'] ?? md5_file($filePath);
        if ($etag === false) {
            fclose($fileStream);

            throw new RuntimeException('Unable to calculate MD5 hash for the file.');
        }

        $fileName = basename($filePath);

        $multipart = [
            [
                'name' => 'file',
                'contents' => $fileStream,
                'filename' => $fileName,
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
                    'name' => (string)$key,
                    'contents' => (string)$value,
                ];
            }
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

        return new FileResource($this->decodeJson($response));
    }

    /**
     * @param array{
     *     mime_type?: string,
     *     chunk_size?: int,
     *     parents?: string[],
     *     created_at?: string,
     *     modified_at?: string,
     *     headers?: array<string, string>,
     *     vault?: string
     * } $options
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
     * @param array{
     *     headers?: array<string, string>,
     *     vault?: string
     * } $options
     */
    public function uploadMultipartPart(
        MultipartUploadSession|string $sessionOrSessionId,
        int                           $partNumber,
        string                        $chunkContents,
        ?string                       $etag = null,
        array                         $options = []
    ): MultipartUploadPart
    {
        $headers = $options['headers'] ?? [];
        $vault = $sessionOrSessionId instanceof MultipartUploadSession ? $sessionOrSessionId->getVault() : null;
        $sessionId = $sessionOrSessionId instanceof MultipartUploadSession ? $sessionOrSessionId->getId() : $sessionOrSessionId;

        $vault = $this->resolveVault($options['vault'] ?? null, $vault);

        $etag ??= md5($chunkContents);
        if ($etag === false) {
            throw new RuntimeException('Unable to calculate MD5 hash for the provided chunk.');
        }

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

        $data = $this->decodeJson($response);

        return new MultipartUploadPart(
            partNumber: isset($data['part_number']) ? (int)$data['part_number'] : $partNumber,
            etag: isset($data['etag']) ? (string)$data['etag'] : $etag,
            attributes: $data,
        );
    }

    /**
     * @param array<int, array{etag: string, part_number: int}> $parts
     * @param array{
     *     headers?: array<string, string>,
     *     vault?: string
     * } $options
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
     * @param array{
     *     headers?: array<string, string>,
     *     vault?: string
     * } $options
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
     * @param array{
     *     parents?: string[],
     *     created_at?: string,
     *     modified_at?: string,
     *     mime_type?: string,
     *     chunk_size?: int,
     *     headers?: array<string, string>,
     *     on_progress?: callable(int $partNumber, int $offset, int $bytesUploaded, int $totalBytes): void,
     *     vault?: string
     * } $options
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

        $session = $this->initializeMultipartUpload($driveId, $fileName, $fileSize, [
            'mime_type' => $mimeType,
            'chunk_size' => $chunkSize,
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

                $partEtag = md5($chunk);
                if ($partEtag === false) {
                    throw new RuntimeException(sprintf('Unable to calculate MD5 hash for part %d.', $partNumber));
                }

                $partResponse = $this->uploadMultipartPart($session, $partNumber, $chunk, $partEtag, [
                    'headers' => $options['headers'] ?? [],
                ]);

                $parts[] = [
                    'etag' => $partResponse->getEtagWithoutQuotes(),
                    'part_number' => $partResponse->getPartNumber(),
                ];

                $bytesUploaded += strlen($chunk);

                if (isset($options['on_progress']) && is_callable($options['on_progress'])) {
                    $options['on_progress']($partNumber, $bytesUploaded - strlen($chunk), $bytesUploaded, (int)$fileSize);
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

    private function request(string $method, Vault $vault, string $uri, array $options): ResponseInterface
    {
        $options['headers'] = $this->mergeHeaders($options['headers'] ?? []);
        $url = rtrim($vault->endpoint, '/') . '/' . ltrim($uri, '/');

        return $this->httpClient->request($method, $url, $options);
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeJson(ResponseInterface $response): array
    {
        $contents = (string)$response->getBody();

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

        return $mimeType === false ? null : $mimeType;
    }

    /**
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
     * @return array{0: string, 1: ?string}
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
}
