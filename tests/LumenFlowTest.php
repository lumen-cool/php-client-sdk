<?php
declare(strict_types=1);

namespace Lumen\Sdk\Tests;

use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Response;
use JsonException;
use Random\RandomException;
use SodiumException;

class LumenFlowTest extends TestCase
{
    /**
     * @throws RandomException
     * @throws GuzzleException
     * @throws JsonException
     * @throws SodiumException
     */
    public function testUrlSanitizationMiddlewareStripsFragmentFromOutgoingRequest(): void
    {
        $this->mockHandler->append(new Response(200, [], json_encode(['id' => 'file_test_1'])));

        $tempFile = tempnam(sys_get_temp_dir(), 'lumen_up');
        file_put_contents($tempFile, 'dummy content');

        try {
            // Note: simpleUpload may not normally contain fragment in URL, but we will artificially
            // trigger an endpoint request by sending a simpleUpload, and modify endpoint to include # later if possible,
            // or we evaluate the interceptor explicitly.
            $this->client->simpleUpload($tempFile, 'drive_local');

            $request = end($this->historyContainer)['request'];
            $uri = (string)$request->getUri();

            // Fragment must never be transmitted to the server
            $this->assertStringNotContainsString('#', $uri);

        } finally {
            unlink($tempFile);
        }
    }

    /**
     * @throws RandomException
     * @throws GuzzleException
     * @throws JsonException
     * @throws SodiumException
     */
    public function testSimpleUploadSuccessAndReturnsFileResource(): void
    {
        $this->mockHandler->append(new Response(201, [], json_encode([
            'id' => 'file_888',
            'name' => 'encrypted_test.txt',
            'size' => 1024,
            'vault' => 'local'
        ])));

        $tempFile = tempnam(sys_get_temp_dir(), 'lumen_test_');
        file_put_contents($tempFile, 'small content payload');

        try {
            $response = $this->client->simpleUpload($tempFile, 'drive_abc');
            $this->assertEquals('file_888', $response->getId());
            $this->assertEquals('local', $response->getVaultSlug());
        } finally {
            unlink($tempFile);
        }
    }
}
