<?php

declare(strict_types=1);

namespace Lumen\Sdk\Response;

final class MultipartUploadResult
{
    private ?FileResource $file;

    /**
     * @param array<string, mixed> $attributes
     */
    public function __construct(private array $attributes)
    {
        $file = $attributes['file'] ?? null;
        $this->file = is_array($file) ? new FileResource($file) : null;
    }

    public function getId(): ?string
    {
        $id = $this->attributes['id'] ?? null;

        return $id !== null ? (string) $id : null;
    }

    public function getUploadId(): ?string
    {
        $uploadId = $this->attributes['upload_id'] ?? null;

        return $uploadId !== null ? (string) $uploadId : null;
    }

    public function getFile(): ?FileResource
    {
        return $this->file;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->attributes;
    }
}
