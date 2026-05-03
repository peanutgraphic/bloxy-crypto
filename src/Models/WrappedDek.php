<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * Represents one DEK wrapped under one KEK.
 *
 * - (owner_user_type, owner_user_id) → which user owns this wrapping
 * - (subject_type, subject_id)       → which record the DEK decrypts
 * - passkey_id                       → which passkey's KEK wraps this DEK
 *                                      (NULL = recovery-key-wrapped variant)
 *
 * Multiple rows per record are normal: one per (record, passkey) pair plus
 * one (record, NULL) recovery row. Adding a 2nd device adds N new rows
 * (one per existing record) wrapped with the new device's KEK.
 */
class WrappedDek extends Model
{
    protected $table = 'wrapped_deks';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'passkey_id' => 'integer',
        ];
    }

    public function scopeForOwner(Builder $query, string $type, string $id): Builder
    {
        return $query->where('owner_user_type', $type)->where('owner_user_id', $id);
    }

    public function scopeForSubject(Builder $query, string $type, string $id): Builder
    {
        return $query->where('subject_type', $type)->where('subject_id', $id);
    }

    public function scopeForPasskey(Builder $query, ?int $passkeyId): Builder
    {
        return $passkeyId === null
            ? $query->whereNull('passkey_id')
            : $query->where('passkey_id', $passkeyId);
    }
}
