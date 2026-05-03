<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Tests\Feature\BloxyUserCryptoModelTest;

use Bloxy\Crypto\Models\BloxyUserCrypto;

it('persists per-user crypto salts', function () {
    $row = BloxyUserCrypto::create([
        'user_type' => 'App\\Models\\User',
        'user_id' => 'u-1',
        'kek_hkdf_salt' => str_repeat('A', 43),
        'recovery_kek_salt' => str_repeat('B', 22),
        'recovery_verifier_salt' => str_repeat('C', 22),
        'recovery_verifier_hash' => str_repeat('D', 22),
    ]);

    expect($row->id)->toBeInt();
    expect(BloxyUserCrypto::find($row->id)->kek_hkdf_salt)->toBe(str_repeat('A', 43));
});

it('enforces unique (user_type, user_id) at the DB layer', function () {
    BloxyUserCrypto::create([
        'user_type' => 'U', 'user_id' => 'u-1',
        'kek_hkdf_salt' => 'a', 'recovery_kek_salt' => 'b',
        'recovery_verifier_salt' => 'c', 'recovery_verifier_hash' => 'd',
    ]);

    expect(fn () => BloxyUserCrypto::create([
        'user_type' => 'U', 'user_id' => 'u-1',
        'kek_hkdf_salt' => 'x', 'recovery_kek_salt' => 'y',
        'recovery_verifier_salt' => 'z', 'recovery_verifier_hash' => 'w',
    ]))->toThrow(\Illuminate\Database\QueryException::class);
});

it('exposes a forUser scope', function () {
    BloxyUserCrypto::create([
        'user_type' => 'U', 'user_id' => 'u-1',
        'kek_hkdf_salt' => 'a', 'recovery_kek_salt' => 'b',
        'recovery_verifier_salt' => 'c', 'recovery_verifier_hash' => 'd',
    ]);

    $found = BloxyUserCrypto::forUser('U', 'u-1')->first();
    expect($found)->not->toBeNull();
    expect($found->user_id)->toBe('u-1');
});
