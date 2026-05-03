<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * Per-user crypto salts. Polymorphic on the consumer's User model so
 * BLOXY doesn't need to know the consumer's user table shape.
 *
 * Stored fields:
 * - kek_hkdf_salt          — 32-byte salt for HKDF-SHA256 KEK derivation
 * - recovery_kek_salt      — 16-byte salt for Argon2id Recovery KEK
 * - recovery_verifier_salt — 16-byte salt for Argon2id verifier hash
 * - recovery_verifier_hash — 16-byte verifier hash (constant-time compared)
 *
 * The PRF salt that bloxy-passkey needs at WebAuthn assertion time is
 * intentionally NOT a column here — that's bloxy-passkey's concern (it
 * can store on the passkey row or extend this table in B1.9.0).
 */
class BloxyUserCrypto extends Model
{
    protected $table = 'bloxy_user_crypto';

    protected $guarded = [];

    public function scopeForUser(Builder $query, string $type, string $id): Builder
    {
        return $query->where('user_type', $type)->where('user_id', $id);
    }
}
