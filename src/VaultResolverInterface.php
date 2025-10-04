<?php

declare(strict_types=1);

namespace Lumen\Sdk;

/**
 * Contract for resolving Lumen vaults.
 *
 * Implementations provide strategies to resolve a Vault instance either by a
 * human-friendly slug or from a full endpoint URL.
 */
interface VaultResolverInterface
{
    /**
     * Resolve a vault by its slug.
     *
     * @param string $slug
     * @return Vault
     */
    public function resolveBySlug(string $slug): Vault;

    /**
     * Resolve a vault from a URL that belongs to that vault's endpoint.
     *
     * @param string $url
     * @return Vault
     */
    public function resolveFromUrl(string $url): Vault;
}
