<?php

declare(strict_types=1);

namespace Lumen\Sdk;

final class Vault
{
    public function __construct(
        public readonly string $slug,
        public readonly string $endpoint,
        public readonly ?int $id = null,
        public readonly ?string $name = null,
        public readonly ?string $createdAt = null,
        public readonly ?string $updatedAt = null,
    ) {
    }

    /**
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
            id: isset($payload['id']) ? (int) $payload['id'] : null,
            name: isset($payload['name']) ? (string) $payload['name'] : null,
            createdAt: isset($payload['created_at']) ? (string) $payload['created_at'] : null,
            updatedAt: isset($payload['updated_at']) ? (string) $payload['updated_at'] : null,
        );
    }
}
