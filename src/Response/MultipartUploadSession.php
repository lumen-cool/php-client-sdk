<?php

declare(strict_types=1);

namespace Lumen\Sdk\Response;

use Lumen\Sdk\Vault;

final class MultipartUploadSession
{
    /**
     * @param array<string, mixed> $attributes
     */
    public function __construct(
        private string $id,
        private string $driveId,
        private Vault $vault,
        private array $attributes,
    ) {
        if (!isset($this->attributes['id'])) {
            $this->attributes['id'] = $this->id;
        }

        if (!isset($this->attributes['drive_id'])) {
            $this->attributes['drive_id'] = $this->driveId;
        }
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getUploadId(): string
    {
        $uploadId = $this->attributes['upload_id'] ?? $this->attributes['id'] ?? $this->id;

        return (string) $uploadId;
    }

    public function getDriveId(): string
    {
        return $this->driveId;
    }

    public function getVault(): Vault
    {
        return $this->vault;
    }

    public function getChunkSize(): ?int
    {
        return isset($this->attributes['chunk_size']) ? (int) $this->attributes['chunk_size'] : null;
    }

    public function getFileName(): ?string
    {
        return isset($this->attributes['file_name']) ? (string) $this->attributes['file_name'] : null;
    }

    public function getFileSize(): ?int
    {
        return isset($this->attributes['file_size']) ? (int) $this->attributes['file_size'] : null;
    }

    public function getMimeType(): ?string
    {
        return isset($this->attributes['mime_type']) ? (string) $this->attributes['mime_type'] : null;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->attributes;
    }
}
