<?php

namespace Lumen\Sdk;

use InvalidArgumentException;
use Stringable;

readonly class FederatedId implements Stringable
{
    public function __construct(
        private string $id,
        private string $slug,
    )
    {

    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getSlug(): string
    {
        return $this->slug;
    }

    /**
     * Extract vault slug from federated ID if present.
     *
     * Federated IDs can optionally include a vault slug suffix in the format:
     * {id}-{vault_slug}
     *
     * @param FederatedId|string $federatedId The federated ID to parse.
     * @return FederatedId
     */
    public static function parse(FederatedId|string $federatedId): static
    {
        if ($federatedId instanceof static) {
            return $federatedId;
        }

        $separator = strrpos($federatedId, '-');
        if ($separator === false) {
            throw new InvalidArgumentException("Invalid federated ID format: missing '-' separator");
        }

        $maybeSlug = substr($federatedId, $separator + 1);
        $maybeId = substr($federatedId, 0, $separator);

        // Validate that the ID part is not empty
        if (empty($maybeId)) {
            throw new InvalidArgumentException("Invalid federated ID format: ID part is empty");
        }
        // Validate that the slug part is not empty
        if (empty($maybeSlug)) {
            throw new InvalidArgumentException("Invalid federated ID format: slug part is empty");
        }

        return new static(id: $maybeId, slug: $maybeSlug);
    }

    public function __toString(): string
    {
        return $this->id . '-' . $this->slug;
    }
}
