<?php

declare(strict_types=1);

namespace Lumen\Sdk;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\ClientInterface;
use RuntimeException;

final class LumenVaultResolver implements VaultResolverInterface
{
    private ClientInterface $httpClient;

    /** @var array<string, Vault> */
    private array $vaultsBySlug = [];

    /** @var array<string, Vault> */
    private array $vaultsByEndpoint = [];

    /** @var array<string, Vault> */
    private array $vaultsByHost = [];

    public function __construct(?ClientInterface $httpClient = null)
    {
        $this->httpClient = $httpClient ?? new GuzzleClient();
    }

    public function addVault(Vault $vault): Vault
    {
        $slugKey = strtolower($vault->slug);
        $normalizedEndpoint = $this->normalizeEndpoint($vault->endpoint);
        $hostKey = $this->normalizeHost($vault->endpoint);

        $this->vaultsBySlug[$slugKey] = $vault;
        $this->vaultsByEndpoint[$normalizedEndpoint] = $vault;

        if ($hostKey !== null) {
            $this->vaultsByHost[$hostKey] = $vault;
        }

        return $vault;
    }

    public function addCustomVault(string $slug, string $endpoint, ?string $name = null, ?int $id = null): Vault
    {
        return $this->addVault(new Vault(
            slug: $slug,
            endpoint: rtrim($endpoint, '/'),
            id: $id,
            name: $name,
            createdAt: null,
            updatedAt: null,
        ));
    }

    public function resolveBySlug(string $slug): Vault
    {
        $key = strtolower($slug);
        if (!isset($this->vaultsBySlug[$key])) {
            throw new RuntimeException(sprintf('Unknown vault slug "%s".', $slug));
        }

        return $this->vaultsBySlug[$key];
    }

    public function resolveFromUrl(string $url): Vault
    {
        $normalizedUrl = $this->normalizeEndpoint($url);
        if (isset($this->vaultsByEndpoint[$normalizedUrl])) {
            return $this->vaultsByEndpoint[$normalizedUrl];
        }

        foreach ($this->vaultsByEndpoint as $endpoint => $vault) {
            if ($endpoint !== '' && str_starts_with($normalizedUrl, $endpoint)) {
                return $vault;
            }
        }

        $hostKey = $this->normalizeHost($url);
        if ($hostKey !== null && isset($this->vaultsByHost[$hostKey])) {
            return $this->vaultsByHost[$hostKey];
        }

        throw new RuntimeException(sprintf('Unable to resolve vault for URL "%s".', $url));
    }

    /**
     * @param array<string, string> $headers
     */
    public function loadFromRegistry(string $registryUrl, array $headers = []): void
    {
        $response = $this->httpClient->request('GET', $registryUrl, [
            'headers' => array_merge(['Accept' => 'application/json'], $headers),
        ]);

        $decoded = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        $vaults = $decoded['data'] ?? null;
        if (!is_array($vaults)) {
            throw new RuntimeException('Vault registry response is missing a "data" array.');
        }

        foreach ($vaults as $vaultDefinition) {
            if (!is_array($vaultDefinition)) {
                continue;
            }

            $this->addVault(Vault::fromArray($vaultDefinition));
        }
    }

    /**
     * @return array<string, Vault>
     */
    public function all(): array
    {
        return $this->vaultsBySlug;
    }

    private function normalizeEndpoint(string $endpoint): string
    {
        $trimmed = rtrim($endpoint, '/');
        $parsed = parse_url($trimmed);

        if ($parsed === false || !isset($parsed['scheme'], $parsed['host'])) {
            return $trimmed;
        }

        $scheme = strtolower((string) $parsed['scheme']);
        $host = strtolower((string) $parsed['host']);
        $port = isset($parsed['port']) ? ':' . $parsed['port'] : '';
        $path = $parsed['path'] ?? '';
        $query = isset($parsed['query']) ? '?' . $parsed['query'] : '';

        return sprintf('%s://%s%s%s%s', $scheme, $host, $port, $path, $query);
    }

    private function normalizeHost(string $endpoint): ?string
    {
        $parsed = parse_url($endpoint);
        if ($parsed === false) {
            return null;
        }

        $host = $parsed['host'] ?? null;
        if (!is_string($host) || $host === '') {
            return null;
        }

        $host = strtolower($host);
        $port = isset($parsed['port']) ? (string) $parsed['port'] : '';
        if ($port !== '') {
            $host .= ':' . $port;
        }

        return $host;
    }
}
