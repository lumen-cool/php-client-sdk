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

    public function getBaseIV(): ?string
    {
        return isset($this->attributes['base_iv']) ? (string)$this->attributes['base_iv'] : null;
    }

    /**
     * Returns the plaintext chunk size used for encryption.
     * This is the size of each chunk of data before encryption overhead is added.
     *
     * @return int|null
     */
    public function getChunkSize(): ?int
    {
        return isset($this->attributes['chunk']) ? (int)$this->attributes['chunk'] : null;
    }
}
