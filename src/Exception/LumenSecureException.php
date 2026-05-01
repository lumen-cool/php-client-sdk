<?php
declare(strict_types=1);

namespace Lumen\Sdk\Exception;

use RuntimeException;
use Throwable;

/**
 * LumenSecureException
 *
 * Secures exception messages by stripping out sensitive URL fragments
 * which may contain encryption keys.
 */
class LumenSecureException extends RuntimeException
{
    public function __construct(string $message = "", int $code = 0, ?Throwable $previous = null)
    {
        // Sanitize the message immediately upon instantiation
        $sanitizedMessage = self::sanitizeMessage($message);
        parent::__construct($sanitizedMessage, $code, $previous);
    }

    /**
     * Removes URL fragments from the given string to prevent key leakage.
     */
    public static function sanitizeMessage(string $message): string
    {
        // Matches '#...' up to the next whitespace, quotation mark, or end of string
        return preg_replace('/#[^\s\'"]+/', '#[REDACTED]', $message);
    }

    /**
     * Override __toString to ensure sanitized output even if the stack trace
     * contains sensitive arguments (though stack traces shouldn't typically
     * contain raw URLs unless part of the message).
     */
    public function __toString(): string
    {
        // Sanitize the parent string representation just in case
        return self::sanitizeMessage(parent::__toString());
    }
}
