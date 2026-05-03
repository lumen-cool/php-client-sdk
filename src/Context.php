<?php

namespace Lumen\Sdk;

readonly class Context
{
    public function __construct(
        private string $id,
        private Vault  $vault,
    )
    {
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getVault(): Vault
    {
        return $this->vault;
    }
}
