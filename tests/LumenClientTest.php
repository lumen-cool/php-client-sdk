<?php
declare(strict_types=1);

namespace Lumen\Sdk\Tests;

class LumenClientTest extends TestCase
{
    public function testGenerateShareableLinkAppendsKeyAsFragment(): void
    {
        $baseUrl = 'https://lumen.cool/share';
        $fileId = 'file_abc123';
        $rawFileKey = 'secret-raw-key-data';

        $link = $this->client->generateShareableLink($baseUrl, $fileId, $rawFileKey);

        // Assert base URL is intact and fragment indicator '#' is present
        $this->assertStringStartsWith("$baseUrl/$fileId#", $link);

        // Extract the fragment and ensure it reverses to the correct raw key
        $parts = explode('#', $link);
        $this->assertCount(2, $parts);

        $encodedKey = $parts[1];
        // Using sodium_bin2base64 or base64url_decode depending on SDK internals,
        // fallback to checking the format matches base64 variants.
        $this->assertEquals($rawFileKey, base64_decode(strtr($encodedKey, '-_', '+/')));
    }
}
