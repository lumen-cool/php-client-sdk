<?php

declare(strict_types=1);

namespace Lumen\Sdk;

/**
 * Value object representing a Lumen vault (storage cluster/tenant).
 */
final class Vault
{
    /**
     * @param string $slug Unique identifier for the vault
     * @param string $endpoint Base API endpoint for this vault
     * @param int|null $id Optional numeric identifier
     * @param string|null $name Human-readable name
     * @param string|null $createdAt Creation timestamp
     * @param string|null $updatedAt Update timestamp
     */
    public function __construct(
        public readonly string  $slug,
        public readonly string  $endpoint,
        public readonly ?int    $id = null,
        public readonly ?string $name = null,
        public readonly ?string $createdAt = null,
        public readonly ?string $updatedAt = null,
    )
    {
    }

    /**
     * Construct a Vault from an associative array (e.g., registry response).
     *
     * @param array<string, mixed> $payload
     */
    public static function fromArray(array $payload): self
    {
        $endpoint = $payload['endpoint'] ?? null;
        $slug = $payload['slug'] ?? null;

        if (!is_string($endpoint) || $endpoint === '') {
            throw new \InvalidArgumentException('Vault endpoint must be provided as a non-empty string.');
        }

        if (!is_string($slug) || $slug === '') {
            throw new \InvalidArgumentException('Vault slug must be provided as a non-empty string.');
        }

        return new self(
            slug: $slug,
            endpoint: rtrim($endpoint, '/'),
            id: isset($payload['id']) ? (int)$payload['id'] : null,
            name: isset($payload['name']) ? (string)$payload['name'] : null,
            createdAt: isset($payload['created_at']) ? (string)$payload['created_at'] : null,
            updatedAt: isset($payload['updated_at']) ? (string)$payload['updated_at'] : null,
        );
    }
}
