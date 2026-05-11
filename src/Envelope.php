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

        // S-20 (Pass 2 M4): reject envelopes carrying keys beyond the
        // canonical 4. An attacker who can write to the DB or intercept
        // JSON in flight could inject extras (e.g. `"alg": "none"`); if
        // any downstream pattern-matches on envelope contents, that's a
        // silent attack surface. Strict shape now: exactly the four
        // SHAPE_KEYS, nothing else.
        if (count($value) !== count(self::SHAPE_KEYS)) {
            $extras = array_diff(array_keys($value), self::SHAPE_KEYS);
            throw PlaintextRejectedException::invalidField(
                'extra keys: ' . implode(', ', array_map('strval', $extras))
            );
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

    /**
     * Decode a JSON-encoded envelope (or envelope-bearing payload) from a
     * database column. Throws PlaintextRejectedException::corruptColumn
     * naming the offending attribute on malformed JSON.
     *
     * Shared between EnvelopeEncrypted and EnvelopeEncryptedJson casts so
     * the JsonException-to-domain-exception wrapper isn't duplicated.
     */
    public static function decodeOrFail(string $key, ?string $json): array
    {
        if ($json === null) {
            throw PlaintextRejectedException::corruptColumn($key, 'value is NULL');
        }
        try {
            $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw PlaintextRejectedException::corruptColumn($key, $e->getMessage());
        }
        if (! is_array($decoded)) {
            throw PlaintextRejectedException::corruptColumn($key, 'decoded value is not an array');
        }
        return $decoded;
    }
}
