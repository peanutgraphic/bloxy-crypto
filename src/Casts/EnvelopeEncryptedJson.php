<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Casts;

use Bloxy\Crypto\Envelope;
use Bloxy\Crypto\Exceptions\PlaintextRejectedException;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Stores a map-of-envelopes as JSON/JSONB. Each VALUE in the map is an
 * envelope; the KEYS are clear (so the server can introspect "does this
 * record have an `ssn` field?" without decrypting it).
 *
 * Used for Tracy ADR-003's hybrid relational + JSONB pattern.
 *
 * On Postgres, declare the column as `jsonb` for indexing on top-level
 * keys; on SQLite, plain `json` works (Laravel's `$t->json()` resolves to
 * the right type per driver).
 */
class EnvelopeEncryptedJson implements CastsAttributes
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

        if (! is_array($decoded)) {
            throw PlaintextRejectedException::notAnEnvelope(gettype($decoded));
        }

        foreach ($decoded as $field => $envelope) {
            Envelope::validate($envelope);
        }

        return $decoded;
    }

    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        if (! is_array($value)) {
            throw PlaintextRejectedException::notAnEnvelope(gettype($value));
        }

        foreach ($value as $field => $envelope) {
            Envelope::validate($envelope);
        }

        return json_encode($value, JSON_THROW_ON_ERROR);
    }
}
