<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Tests\Feature\WrappedDekModelTest;

use Bloxy\Crypto\Models\WrappedDek;

it('persists a wrapped DEK row', function () {
    $row = WrappedDek::create([
        'owner_user_type' => 'App\\Models\\User',
        'owner_user_id' => '550e8400-e29b-41d4-a716-446655440000',
        'subject_type' => 'App\\Models\\Secret',
        'subject_id' => '660e8400-e29b-41d4-a716-446655440000',
        'passkey_id' => 42,
        'wrapped_dek_text' => 'YmFzZTY0LXdyYXBwZWQ',
    ]);

    expect($row->id)->toBeInt();
    expect(WrappedDek::find($row->id)->passkey_id)->toBe(42);
});

it('allows null passkey_id for recovery-key-wrapped variant', function () {
    $row = WrappedDek::create([
        'owner_user_type' => 'App\\Models\\User',
        'owner_user_id' => 'u-1',
        'subject_type' => 'App\\Models\\Secret',
        'subject_id' => 's-1',
        'passkey_id' => null,
        'wrapped_dek_text' => 'recovery-wrapped',
    ]);

    expect($row->passkey_id)->toBeNull();
});

it('exposes scopes for owner and subject lookup', function () {
    WrappedDek::create([
        'owner_user_type' => 'U', 'owner_user_id' => 'u-1',
        'subject_type' => 'S', 'subject_id' => 's-1',
        'passkey_id' => 1, 'wrapped_dek_text' => 'a',
    ]);
    WrappedDek::create([
        'owner_user_type' => 'U', 'owner_user_id' => 'u-1',
        'subject_type' => 'S', 'subject_id' => 's-2',
        'passkey_id' => 1, 'wrapped_dek_text' => 'b',
    ]);
    WrappedDek::create([
        'owner_user_type' => 'U', 'owner_user_id' => 'u-2',
        'subject_type' => 'S', 'subject_id' => 's-1',
        'passkey_id' => 1, 'wrapped_dek_text' => 'c',
    ]);

    expect(WrappedDek::forOwner('U', 'u-1')->count())->toBe(2);
    expect(WrappedDek::forSubject('S', 's-1')->count())->toBe(2);
});
