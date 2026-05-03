<?php

declare(strict_types=1);

namespace Bloxy\Crypto;

use Bloxy\Crypto\Exceptions\PlaintextRejectedException;

/**
 * Envelope is the wire format for a single encrypted field.
 *
 * Shape:
 *   {
 *     "v": 1,                              // schema version
 *     "nonce": "<base64url>",              // 24-byte secretbox nonce
 *     "ciphertext": "<base64url>",         // libsodium secretbox output
 *     "wrapped_dek": "<base64url>"         // DEK wrapped under KEK
 *   }
 *
 * The server treats this as opaque JSON. Validation only checks shape,
 * not cryptographic validity (the server cannot verify the latter without
 * the KEK).
 *
 * The same shape is encoded by the TS half (see crypto-js/src/envelope.ts).
 * Any change here MUST be matched on the TS side and ship as a v2 envelope
 * with a migration path for v1 rows.
 */
final class Envelope
{
    public const CURRENT_VERSION = 1;

    public const SHAPE_KEYS = ['v', 'nonce', 'ciphertext', 'wrapped_dek'];

    /**
     * Validates that $value is a well-formed envelope JSON struct (already
     * decoded into an array). Throws PlaintextRejectedException if not.
     *
     * Does NOT verify the ciphertext — the server can't.
     *
     * Note: `get()` callers also pass values through this method, so rows written
     * by a future v2 client throw on this server until it's updated.
     */
    public static function validate(mixed $value): void
    {
        if (! is_array($value)) {
            throw PlaintextRejectedException::notAnEnvelope(gettype($value));
        }

        foreach (self::SHAPE_KEYS as $key) {
            if (! array_key_exists($key, $value)) {
                throw PlaintextRejectedException::missingKey($key);
            }
        }

        if (! is_int($value['v']) || $value['v'] !== self::CURRENT_VERSION) {
            throw PlaintextRejectedException::invalidVersion($value['v']);
        }

        foreach (['nonce', 'ciphertext', 'wrapped_dek'] as $b64) {
            if (! is_string($value[$b64]) || $value[$b64] === '') {
                throw PlaintextRejectedException::invalidField($b64);
            }
        }
    }
}
