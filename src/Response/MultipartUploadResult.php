<?php

declare(strict_types=1);

namespace Lumen\Sdk\Response;

final class MultipartUploadResult
{
    private File $file;

    /**
     * @param array<string, mixed> $attributes
     */
    public function __construct(private readonly array $attributes)
    {
        $this->file = new File($attributes['file']);
    }

    public function getId(): string
    {
        return $this->attributes['id'];
    }

    public function getFile(): File
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
