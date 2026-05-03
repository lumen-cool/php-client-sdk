<?php

namespace Lumen\Sdk\Response;

readonly class FileEncryption
{
    /**
     * @param array<string, mixed> $attributes
     */
    public function __construct(private array $attributes)
    {
        //
    }

    public function getAlgorithm(): ?string
    {
        return isset($this->attributes['alg']) ? (string)$this->attributes['alg'] : null;
    }

    public function getVersion(): ?string
    {
        return isset($this->attributes['v']) ? (string)$this->attributes['v'] : null;
    }

    public function getWrappedKey(): ?string
    {
        return isset($this->attributes['wrapped_key']) ? (string)$this->attributes['wrapped_key'] : null;
    }

    public function getRawWrappedKey(): ?string
    {
        $wrappedKey = $this->getWrappedKey();
        if ($wrappedKey === null) {
            return null;
        }
        return base64_decode($wrappedKey, true);
    }

    public function getBaseIV(): ?string
    {
        return isset($this->attributes['base_iv']) ? (string)$this->attributes['base_iv'] : null;
    }

    public function getRawBaseIV(): ?string
    {
        $baseIV = $this->getBaseIV();
        if ($baseIV === null) {
            return null;
        }
        return base64_decode($baseIV, true);
    }

    public function getChunkSize(): ?int
    {
        return isset($this->attributes['chunk']) ? (int)$this->attributes['chunk'] : null;
    }
}
