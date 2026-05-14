<?php

declare(strict_types=1);

/*
 * Full envelope round-trip test for B-7.
 *
 * Validates that a JS-encrypted envelope (with deterministic nonces) passes
 * PHP's Envelope::validate() and that the wire shape is exactly canonical.
 * The decrypt half is exercised on the JS side; see
 * packages/crypto-js/tests/envelope-roundtrip.test.ts.
 *
 * Fixture: packages/crypto-php/tests/fixtures/envelope-roundtrip-v1.json
 * The fixture is generated deterministically (fixed key/dek/nonces) so PHP
 * and JS test runs agree on byte content; it is committed and read by both.
 */

use Bloxy\Crypto\Envelope;

it('accepts a deterministically-generated envelope and exposes its canonical shape', function () {
    $fixturePath = __DIR__ . '/../fixtures/envelope-roundtrip-v1.json';
    $fixture = json_decode(file_get_contents($fixturePath), true, flags: JSON_THROW_ON_ERROR);

    $envelope = $fixture['envelope'];

    // Shape validation MUST NOT throw for a well-formed envelope.
    Envelope::validate($envelope);

    // Pin the canonical shape: exactly the 4 SHAPE_KEYS, no extras.
    expect(array_keys($envelope))->toEqualCanonicalizing(Envelope::SHAPE_KEYS);
    expect($envelope['v'])->toBe(Envelope::CURRENT_VERSION);
    expect($envelope['nonce'])->toBeString()->not->toBe('');
    expect($envelope['ciphertext'])->toBeString()->not->toBe('');
    expect($envelope['wrapped_dek'])->toBeString()->not->toBe('');
});
