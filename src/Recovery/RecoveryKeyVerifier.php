<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Recovery;

use Bloxy\Crypto\Models\BloxyUserCrypto;
use Illuminate\Contracts\Config\Repository as Config;

/**
 * Verifies a candidate recovery phrase against a stored Argon2id verifier
 * hash on the BloxyUserCrypto row.
 *
 * The KEK derivation (separate Argon2id call using recovery_kek_salt) is
 * client-side; this verifier only confirms the user knows the phrase.
 *
 * Constant-time compare via hash_equals — the early-out on length mismatch
 * is acceptable: the verifier hash length is fixed by config, not user data.
 */
class RecoveryKeyVerifier
{
    public function __construct(private Config $config) {}

    public function verify(BloxyUserCrypto $row, string $candidatePhrase): bool
    {
        if ($candidatePhrase === '') {
            return false;
        }

        try {
            $salt = sodium_base642bin(
                $row->recovery_verifier_salt,
                SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING
            );
        } catch (\SodiumException $e) {
            // Stored salt is malformed — server data integrity bug, not an auth
            // failure. Log loudly so operators can investigate; return false so
            // the auth response stays safe-default (no leak about row state).
            \Illuminate\Support\Facades\Log::error(
                'bloxy-crypto: corrupt recovery_verifier_salt on BloxyUserCrypto row',
                ['row_id' => $row->id, 'sodium_error' => $e->getMessage()]
            );
            return false;
        }

        $candidateHash = sodium_crypto_pwhash(
            16,
            $candidatePhrase,
            $salt,
            (int) $this->config->get('bloxy-crypto.recovery.argon2id_time', 4),
            (int) $this->config->get('bloxy-crypto.recovery.argon2id_memory_kb', 65536) * 1024,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );

        $candidateB64 = sodium_bin2base64(
            $candidateHash,
            SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING
        );

        // S-22 (Pass 2 M4): defense-in-depth length check. The column is
        // varchar(32) but a 16-byte Argon2id output base64url-encodes to
        // exactly 22 chars. If the stored value is ever a different
        // length (corrupted row, future migration extending the column,
        // operator error), hash_equals's documented short-circuit on
        // length mismatch produces a fast-false that's distinguishable
        // via timing. Detect the mismatch explicitly and log it; the
        // function still returns false but the cause is observable.
        $expectedLen = 22;
        if (strlen((string) $row->recovery_verifier_hash) !== $expectedLen) {
            \Illuminate\Support\Facades\Log::error(
                'bloxy-crypto: recovery_verifier_hash has unexpected length',
                [
                    'user_type' => $row->user_type,
                    'user_id' => $row->user_id,
                    'expected_len' => $expectedLen,
                    'actual_len' => strlen((string) $row->recovery_verifier_hash),
                ],
            );
            return false;
        }

        return hash_equals($row->recovery_verifier_hash, $candidateB64);
    }
}
