<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Exceptions;

use RuntimeException;

/**
 * Thrown when a non-envelope value is set on an EnvelopeEncrypted cast.
 *
 * The cast NEVER encrypts plaintext server-side — that would defeat the
 * zero-knowledge property. Plaintext arrives at the server only because
 * the client failed to encrypt it (missing BloxyCryptoProvider, KEK not
 * loaded, etc.); the right answer is to fail loudly so the bug is visible
 * during development rather than silently storing PII unprotected.
 */
final class PlaintextRejectedException extends RuntimeException
{
    public static function notAnEnvelope(string $actualType): self
    {
        return new self(
            "EnvelopeEncrypted cast received a {$actualType} value; expected an envelope array. "
            . "The client must encrypt this field before submission. See docs/crypto.md."
        );
    }

    public static function missingKey(string $key): self
    {
        return new self(
            "EnvelopeEncrypted value is missing required key '{$key}'. "
            . "Expected shape: " . implode(', ', \Bloxy\Crypto\Envelope::SHAPE_KEYS)
        );
    }

    public static function invalidVersion(mixed $version): self
    {
        $shown = is_scalar($version) ? (string) $version : gettype($version);
        return new self(
            "EnvelopeEncrypted value has unsupported version '{$shown}'; "
            . "this server understands v" . \Bloxy\Crypto\Envelope::CURRENT_VERSION . "."
        );
    }

    public static function invalidField(string $key): self
    {
        return new self(
            "EnvelopeEncrypted field '{$key}' must be a non-empty base64url string."
        );
    }

    public static function corruptColumn(string $key, string $jsonError): self
    {
        return new self(
            "EnvelopeEncrypted column '{$key}' contains invalid JSON: {$jsonError}. "
            . "The row was likely hand-edited or written by an incompatible version."
        );
    }
}
