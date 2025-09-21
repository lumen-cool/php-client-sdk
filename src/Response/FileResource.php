<?php

declare(strict_types=1);

namespace Lumen\Sdk\Response;

final class FileResource
{
    /**
     * @param array<string, mixed> $attributes
     */
    public function __construct(private array $attributes)
    {
    }

    public function getId(): string
    {
        return (string) $this->attributes['id'];
    }

    public function getName(): ?string
    {
        return isset($this->attributes['name']) ? (string) $this->attributes['name'] : null;
    }

    public function getDriveId(): ?string
    {
        return isset($this->attributes['drive_id']) ? (string) $this->attributes['drive_id'] : null;
    }

    public function getMimeType(): ?string
    {
        return isset($this->attributes['mime_type']) ? (string) $this->attributes['mime_type'] : null;
    }

    public function getSize(): ?int
    {
        return isset($this->attributes['size']) ? (int) $this->attributes['size'] : null;
    }

    public function getVaultSlug(): ?string
    {
        return isset($this->attributes['vault']) ? (string) $this->attributes['vault'] : null;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->attributes;
    }
}
