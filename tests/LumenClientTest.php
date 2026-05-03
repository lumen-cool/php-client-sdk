<?php
declare(strict_types=1);

namespace Lumen\Sdk\Tests;

use Lumen\Sdk\Response\File;

class LumenClientTest extends TestCase
{
    public function testGenerateShareableLinkAppendsKeyAsFragment(): void
    {
        $baseUrl = 'https://app.lumen.cool';
        $fileId = 'file_abc123';
        $vaultSlug = 'vault_xyz';
        $rawFileKey = 'secret-raw-key-data';

        $file = new File([
            'id' => $fileId,
            'vault' => $vaultSlug,
            'encryption' => [
                'wrapped_key' => base64_encode($rawFileKey),
            ],
        ]);

        $link = $this->client->generateShareableLink($file);

        // Assert base URL is intact and fragment indicator '#' is present
        $this->assertStringStartsWith("$baseUrl/files/$fileId-$vaultSlug/view#", $link->getFullUrl());

        // Extract the fragment and ensure it reverses to the correct raw key
        $parts = explode('#', $link->getFullUrl());
        $this->assertCount(2, $parts);

        $encodedKey = $parts[1];
        // Using sodium_bin2base64 or base64url_decode depending on SDK internals,
        // fallback to checking the format matches base64 variants.
        $this->assertEquals($rawFileKey, base64_decode(strtr($encodedKey, '-_', '+/')));
    }
}
