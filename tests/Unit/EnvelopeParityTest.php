<?php

declare(strict_types=1);

/*
 * Cross-language byte-parity test for B-7.
 *
 * Pins that PHP's ext-sodium produces the same secretbox ciphertext as
 * JS's libsodium-wrappers-sumo for the same key + nonce + plaintext.
 * Companion JS test: packages/crypto-js/tests/envelope-parity.test.ts
 *
 * Fixture: packages/crypto-php/tests/fixtures/envelope-parity-v1.json
 * Both sides read the fixture and assert their independently-computed
 * ciphertext matches the stored canonical value byte-for-byte.
 */

function b64url_decode(string $b): string
{
    $b = strtr($b, '-_', '+/');
    $pad = (4 - (strlen($b) % 4)) % 4;
    return base64_decode($b . str_repeat('=', $pad), true);
}

function b64url_encode(string $b): string
{
    return rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
}

it('PHP libsodium ciphertext matches the cross-language fixture', function () {
    $fixturePath = __DIR__ . '/../fixtures/envelope-parity-v1.json';
    $fixture = json_decode(file_get_contents($fixturePath), true, flags: JSON_THROW_ON_ERROR);

    $key = b64url_decode($fixture['key_b64url']);
    $nonce = b64url_decode($fixture['nonce_b64url']);
    $plaintext = $fixture['plaintext'];
    $expected = $fixture['ciphertext_b64url'];

    $cipher = sodium_crypto_secretbox($plaintext, $nonce, $key);

    expect(b64url_encode($cipher))->toBe($expected);
});
