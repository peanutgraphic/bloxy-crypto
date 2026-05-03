<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Casts;

use Bloxy\Crypto\Envelope;
use Bloxy\Crypto\Exceptions\PlaintextRejectedException;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Stores a client-encrypted envelope as JSON in a text column.
 *
 * The server CANNOT decrypt these values — the KEK is held client-side only.
 * `set()` validates envelope shape but does not validate ciphertext (the
 * server has no key to verify with). `get()` returns the decoded envelope
 * struct unchanged for the client to decrypt.
 *
 * Use on a `text` (or larger) column; envelopes are typically 200–400 bytes.
 *
 * Plaintext values passed to `set()` are REJECTED with
 * PlaintextRejectedException — the cast never silently encrypts server-side.
 */
class EnvelopeEncrypted implements CastsAttributes
{
    public function get(Model $model, string $key, mixed $value, array $attributes): ?array
    {
        if ($value === null) {
            return null;
        }

        try {
            $decoded = json_decode((string) $value, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw PlaintextRejectedException::corruptColumn($key, $e->getMessage());
        }

        Envelope::validate($decoded);

        return $decoded;
    }

    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        Envelope::validate($value);

        return json_encode($value, JSON_THROW_ON_ERROR);
    }
}
