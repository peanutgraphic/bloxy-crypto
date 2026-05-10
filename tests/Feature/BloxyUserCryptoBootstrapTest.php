<?php

declare(strict_types=1);

use Bloxy\Crypto\Models\BloxyUserCrypto;

it('bootstraps a fresh user crypto row with all required salts and a verifier sentinel', function () {
    $row = BloxyUserCrypto::bootstrap('App\\Models\\User', 'user-123');

    expect($row)->toBeInstanceOf(BloxyUserCrypto::class);
    expect($row->user_type)->toBe('App\\Models\\User');
    expect($row->user_id)->toBe('user-123');

    // Salts are base64url strings; check they round-trip to the documented
    // raw-byte sizes rather than asserting on string length directly.
    $b64 = fn (string $s) => strlen(base64_decode(strtr($s, '-_', '+/'), true));
    expect($b64($row->kek_hkdf_salt))->toBe(32);
    expect($b64($row->recovery_kek_salt))->toBe(16);
    expect($b64($row->recovery_verifier_salt))->toBe(16);

    expect($row->recovery_verifier_hash)->toBe(str_repeat('A', 22));
});

it('is idempotent — re-bootstrapping returns the existing row without regenerating salts', function () {
    $first = BloxyUserCrypto::bootstrap('App\\Models\\User', 'user-456');
    $second = BloxyUserCrypto::bootstrap('App\\Models\\User', 'user-456');

    expect($second->id)->toBe($first->id);
    expect($second->kek_hkdf_salt)->toBe($first->kek_hkdf_salt);
    expect($second->recovery_kek_salt)->toBe($first->recovery_kek_salt);
});

it('isolates rows by user type', function () {
    $userRow = BloxyUserCrypto::bootstrap('App\\Models\\User', 'shared-id');
    $contractorRow = BloxyUserCrypto::bootstrap('App\\Models\\Contractor', 'shared-id');

    expect($contractorRow->id)->not->toBe($userRow->id);
    expect($contractorRow->user_type)->toBe('App\\Models\\Contractor');
});

it('generates distinct salts across calls for different users', function () {
    $a = BloxyUserCrypto::bootstrap('App\\Models\\User', 'u-a');
    $b = BloxyUserCrypto::bootstrap('App\\Models\\User', 'u-b');

    expect($a->kek_hkdf_salt)->not->toBe($b->kek_hkdf_salt);
    expect($a->recovery_kek_salt)->not->toBe($b->recovery_kek_salt);
});
