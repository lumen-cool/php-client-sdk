<?php

declare(strict_types=1);

namespace Lumen\Sdk\Response;

final class MultipartUploadPart
{
    /**
     * @param array<string, mixed> $attributes
     */
    public function __construct(
        private int $partNumber,
        private string $etag,
        private array $attributes = [],
    ) {
        $this->attributes = array_merge(
            ['part_number' => $this->partNumber, 'etag' => $this->etag],
            $this->attributes,
        );
    }

    public function getPartNumber(): int
    {
        return $this->partNumber;
    }

    public function getEtag(): string
    {
        return $this->etag;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->attributes;
    }
}
