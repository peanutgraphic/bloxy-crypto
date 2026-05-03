<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Mock;

use Bloxy\Crypto\Envelope;
use RuntimeException;

/**
 * Identity-shaped XOR wrap for seeders + factories + dev fixtures.
 *
 * Produces envelope-shaped values that pass cast validation but offer NO
 * real protection — the "ciphertext" is plaintext XORed with a known
 * sentinel byte. Useful for:
 * - Database seeders that need realistic-shaped data
 * - Eloquent factories
 * - Test fixtures where the test asserts on shape, not on confidentiality
 *
 * Refused in production by BloxyCryptoServiceProvider's boot() guard.
 *
 * The TS half (crypto-js/src/mock.ts) implements the SAME wrap so a row
 * created via PHP MockWrap can be "decrypted" via JS unwrapMock and vice
 * versa — useful for end-to-end tests that span server and client.
 */
final class MockWrap
{
    public const SENTINEL = "\x42"; // arbitrary, must match JS mock.ts SENTINEL

    public static function envelope(string $plaintext): array
    {
        if (config('bloxy-crypto.mock', false) !== true) {
            throw new RuntimeException(
                'MockWrap::envelope() called but bloxy-crypto.mock is not enabled. '
                . 'Set BLOXY_CRYPTO_MOCK=true (non-production only).'
            );
        }

        $xored = self::xorWithSentinel($plaintext);

        return [
            'v' => Envelope::CURRENT_VERSION,
            'nonce' => sodium_bin2base64(str_repeat("\x00", 24), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
            'ciphertext' => sodium_bin2base64($xored, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
            'wrapped_dek' => sodium_bin2base64(str_repeat(self::SENTINEL, 32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
        ];
    }

    public static function unwrap(array $envelope): string
    {
        if (config('bloxy-crypto.mock', false) !== true) {
            throw new RuntimeException(
                'MockWrap::unwrap() called but bloxy-crypto.mock is not enabled. '
                . 'Use the JS-side bloxy-crypto decryptField() for real envelopes.'
            );
        }

        Envelope::validate($envelope);

        $cipher = sodium_base642bin(
            $envelope['ciphertext'],
            SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING
        );

        return self::xorWithSentinel($cipher);
    }

    private static function xorWithSentinel(string $bytes): string
    {
        $out = '';
        $len = strlen($bytes);
        for ($i = 0; $i < $len; $i++) {
            $out .= $bytes[$i] ^ self::SENTINEL;
        }
        return $out;
    }
}
