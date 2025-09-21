<?php

declare(strict_types=1);

namespace Lumen\Sdk\Response;

final class MultipartUploadResult
{
    private FileResource $file;

    /**
     * @param array<string, mixed> $attributes
     */
    public function __construct(private array $attributes)
    {
        $this->file = new FileResource($attributes['file']);
    }

    public function getId(): string
    {
        return $this->attributes['id'];
    }

    public function getFile(): FileResource
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
