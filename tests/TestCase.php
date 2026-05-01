<?php
declare(strict_types=1);

namespace Lumen\Sdk\Tests;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use Lumen\Sdk\LumenClient;
use Lumen\Sdk\LumenVaultResolver;
use Lumen\Sdk\Middleware\UrlSanitizationMiddleware;
use PHPUnit\Framework\TestCase as Base;

class TestCase extends Base
{
    protected LumenClient $client;
    protected MockHandler $mockHandler;
    protected array $historyContainer = [];

    protected function setUp(): void
    {
        $this->mockHandler = new MockHandler();
        $handlerStack = HandlerStack::create($this->mockHandler);

        // Test defensive middleware is in the stack
        $handlerStack->push(UrlSanitizationMiddleware::create());
        $handlerStack->push(Middleware::history($this->historyContainer));

        $httpClient = new GuzzleClient(['handler' => $handlerStack]);
        $resolver = new LumenVaultResolver();
        $resolver->addCustomVault('local', 'http://localhost:8000', 'Local development');

        $this->client = new LumenClient(
            vaultResolver: $resolver,
            httpClient: $httpClient,
            defaultHeaders: [
                'Authorization' => 'Bearer YOUR_TOKEN',
            ],
        );
        $this->client->setVault('local');
    }
}
