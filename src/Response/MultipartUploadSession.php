<?php

declare(strict_types=1);

namespace Lumen\Sdk\Response;

use Lumen\Sdk\Vault;

final readonly class MultipartUploadSession
{
    /**
     * @param array<string, mixed> $attributes
     */
    public function __construct(
        private array $attributes,
        private Vault $vault,
    )
    {
        //
    }

    public function getId(): string
    {
        return $this->attributes['session']['id'];
    }

    public function getVault(): Vault
    {
        return $this->vault;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->attributes;
    }
}
