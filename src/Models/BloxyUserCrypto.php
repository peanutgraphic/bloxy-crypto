<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Models;

use Bloxy\Core\Support\Base64Url;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Schema;

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

    /**
     * Idempotently create a per-user crypto row with fresh salts and a
     * sentinel verifier hash. Returns the existing row if one already
     * exists for ($userType, $userId) — does not regenerate salts in that
     * case (regenerating would invalidate every wrapped_dek for the user).
     *
     * Salt sizes match the conventions used across BLOXY consumers:
     *   - kek_hkdf_salt:          32 raw bytes (44 base64url chars after encode)
     *   - prf_salt:               32 raw bytes (only set if the column exists,
     *                             which it does once bloxy-passkey is installed)
     *   - recovery_kek_salt:      16 raw bytes (22 base64url chars)
     *   - recovery_verifier_salt: 16 raw bytes (22 base64url chars)
     *
     * recovery_verifier_hash is set to a 22-char sentinel ('A' x 22) so
     * the column is non-null and `verifier_hash !== sentinel` is the
     * "real verifier issued" predicate. Consumer call sites can compare
     * against str_repeat('A', 22) to gate re-issuance.
     */
    public static function bootstrap(string $userType, string $userId): self
    {
        $attrs = [
            'kek_hkdf_salt' => Base64Url::encode(random_bytes(32)),
            'recovery_kek_salt' => Base64Url::encode(random_bytes(16)),
            'recovery_verifier_salt' => Base64Url::encode(random_bytes(16)),
            'recovery_verifier_hash' => str_repeat('A', 22),
        ];

        if (Schema::hasColumn('bloxy_user_crypto', 'prf_salt')) {
            $attrs['prf_salt'] = Base64Url::encode(random_bytes(32));
        }

        return self::firstOrCreate(
            ['user_type' => $userType, 'user_id' => $userId],
            $attrs,
        );
    }
}
