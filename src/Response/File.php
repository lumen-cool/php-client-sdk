<?php

declare(strict_types=1);

namespace Lumen\Sdk\Response;

use Lumen\Sdk\FederatedId;

final readonly class File
{
    /**
     * @param array<string, mixed> $attributes
     */
    public function __construct(private array $attributes)
    {
        //
    }

    /**
     * Get a unique federated ID for the file, combining the file ID and vault slug.
     */
    public function getFederatedId(): FederatedId
    {
        return new FederatedId(id: $this->getId(), slug: $this->getVaultSlug());
    }

    /**
     * Get the unique file ID.
     */
    public function getId(): string
    {
        return (string)$this->attributes['id'];
    }

    public function getName(): ?string
    {
        return isset($this->attributes['name']) ? (string)$this->attributes['name'] : null;
    }

    public function getDriveId(): ?string
    {
        return isset($this->attributes['drive_id']) ? (string)$this->attributes['drive_id'] : null;
    }

    public function getMimeType(): ?string
    {
        return isset($this->attributes['mime_type']) ? (string)$this->attributes['mime_type'] : null;
    }

    public function getSize(): ?int
    {
        return isset($this->attributes['size']) ? (int)$this->attributes['size'] : null;
    }

    public function getDownloadUrl(): ?string
    {
        return isset($this->attributes['download_url']) ? (string)$this->attributes['download_url'] : null;
    }

    public function getEncryption(): ?FileEncryption
    {
        return isset($this->attributes['encryption']) && is_array($this->attributes['encryption'])
            ? new FileEncryption($this->attributes['encryption'])
            : null;
    }

    public function getVaultSlug(): ?string
    {
        return isset($this->attributes['vault']) ? (string)$this->attributes['vault'] : null;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->attributes;
    }

    public function getChunkSize(): ?int
    {
        return isset($this->attributes['chunk_size']) ? (int)$this->attributes['chunk_size'] : null;
    }
}
