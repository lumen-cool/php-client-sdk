<?php

namespace Lumen\Sdk;

use InvalidArgumentException;
use Stringable;

readonly class ShareableLink implements Stringable
{
    public function __construct(
        private string  $url,
        private ?string $encodedKey = null,
    )
    {
    }

    /**
     * @return string The base URL for shareable links, when constructing shareable link URLs.
     */
    public static function baseUrl(): string
    {
        return 'https://app.lumen.cool';
    }

    /**
     * @return string The base URL of the shareable link, without any encoded key fragment.
     */
    public function getUrl(): string
    {
        return $this->url;
    }

    /**
     * @return string The full shareable link URL, including the encoded key fragment if present (e.g. https://lumen.com/s/abc-123/view#secret).
     */
    public function getFullUrl(): string
    {
        if ($this->encodedKey) {
            return sprintf('%s#%s', $this->url, $this->encodedKey);
        }
        return $this->url;
    }

    /**
     * @return string|null The encoded key fragment from the shareable link URL, or null if not present.
     */
    public function getEncodedKey(): ?string
    {
        return $this->encodedKey;
    }

    /**
     * Create a ShareableLink instance from a shareable link URL.
     * The URL may contain a encoded key fragment, e.g. https://lumen.com/s/abc-123/view#secret
     *
     * @param string $url The shareable link URL, which may include a encoded key fragment.
     * @return ShareableLink A new ShareableLink instance with the URL and optional encoded key extracted.
     */
    public static function fromUrl(string $url): self
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host'], $parts['path'])) {
            throw new InvalidArgumentException("Invalid URL: $url");
        }

        $baseUrl = sprintf('%s://%s', $parts['scheme'], $parts['host']);
        if (isset($parts['port'])) {
            $baseUrl .= ':' . $parts['port'];
        }
        $baseUrl .= rtrim($parts['path'], '/');

        $encodedKey = isset($parts['fragment']) ? (string)$parts['fragment'] : null;

        return new self($baseUrl, $encodedKey);
    }

    /**
     * @return string A string representation of the shareable link, combining the URL and encoded key if present.
     */
    public function __toString(): string
    {
        return $this->getFullUrl();
    }
}
