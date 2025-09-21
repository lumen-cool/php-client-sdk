<?php

declare(strict_types=1);

namespace Lumen\Sdk;

interface VaultResolverInterface
{
    public function resolveBySlug(string $slug): Vault;

    public function resolveFromUrl(string $url): Vault;
}
