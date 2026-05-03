<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Tests\Feature\RecoveryKeyVerifierTest;

use Bloxy\Crypto\Models\BloxyUserCrypto;
use Bloxy\Crypto\Recovery\RecoveryKeyVerifier;

beforeEach(function () {
    config()->set('bloxy-crypto.recovery.argon2id_time', 1);     // fast for tests
    config()->set('bloxy-crypto.recovery.argon2id_memory_kb', 1024);
});

function makeUserCrypto(string $words, string $verifierSalt): BloxyUserCrypto
{
    $hash = sodium_crypto_pwhash(
        16,
        $words,
        sodium_base642bin($verifierSalt, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
        1, 1024 * 1024,
        SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
    );

    return BloxyUserCrypto::create([
        'user_type' => 'U', 'user_id' => 'u-1',
        'kek_hkdf_salt' => str_repeat('A', 43),
        'recovery_kek_salt' => str_repeat('B', 22),
        'recovery_verifier_salt' => $verifierSalt,
        'recovery_verifier_hash' => sodium_bin2base64($hash, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
    ]);
}

it('returns true for the correct recovery phrase', function () {
    $words = 'abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual';
    $verifierSalt = sodium_bin2base64(random_bytes(16), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $row = makeUserCrypto($words, $verifierSalt);

    $verifier = app(RecoveryKeyVerifier::class);
    expect($verifier->verify($row, $words))->toBeTrue();
});

it('returns false for a wrong recovery phrase', function () {
    $verifierSalt = sodium_bin2base64(random_bytes(16), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $row = makeUserCrypto('correct words here', $verifierSalt);

    $verifier = app(RecoveryKeyVerifier::class);
    expect($verifier->verify($row, 'wrong words here'))->toBeFalse();
});

it('returns false for an empty phrase without throwing', function () {
    $verifierSalt = sodium_bin2base64(random_bytes(16), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $row = makeUserCrypto('correct', $verifierSalt);

    $verifier = app(RecoveryKeyVerifier::class);
    expect($verifier->verify($row, ''))->toBeFalse();
});
