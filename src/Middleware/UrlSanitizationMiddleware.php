<?php
declare(strict_types=1);

namespace Lumen\Sdk\Middleware;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Promise\PromiseInterface;
use Lumen\Sdk\Exception\LumenSecureException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Throwable;

/**
 * UrlSanitizationMiddleware
 *
 * Intercepts Guzzle requests and responses to ensure any URL fragment
 * (which might contain the raw encryption key) never gets leaked into
 * the typical RequestException / ConnectException messages.
 */
class UrlSanitizationMiddleware
{
    public function __invoke(callable $handler): callable
    {
        return function (RequestInterface $request, array $options) use ($handler): PromiseInterface {

            // First, proactively strip the fragment from the outgoing request URL
            // because fragments should not be sent to the server anyway.
            $uri = $request->getUri();
            if ($uri->getFragment() !== '') {
                $request = $request->withUri($uri->withFragment(''));
            }

            return $handler($request, $options)->then(
                function (ResponseInterface $response) {
                    return $response;
                },
                function (Throwable $reason) {
                    // Wrap Guzzle exceptions that might contain the URL in their message
                    if ($reason instanceof RequestException || $reason instanceof ConnectException) {
                        $sanitizedMessage = LumenSecureException::sanitizeMessage($reason->getMessage());

                        throw new LumenSecureException(
                            "Secure Request Error: " . $sanitizedMessage,
                            $reason->getCode(),
                            $reason
                        );
                    }

                    // For other throwable, just pass it through or wrap
                    throw $reason;
                }
            );
        };
    }
}
