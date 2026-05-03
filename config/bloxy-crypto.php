<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | MOCK mode
    |--------------------------------------------------------------------------
    |
    | When true, the envelope casts and WrappedDek seeding helpers use an
    | identity-shaped XOR wrap instead of real libsodium operations. This is
    | useful for seeders, factories, and any test setup that needs to produce
    | envelope-shaped rows without a real authenticator.
    |
    | The BloxyCryptoServiceProvider's boot() method REFUSES to enable MOCK
    | mode in production (App::environment(['production'])). Attempting to
    | boot with mock=true in production throws a RuntimeException at framework
    | boot — the app fails to start, intentionally, rather than silently
    | running with toy crypto in production.
    |
    */
    'mock' => env('BLOXY_CRYPTO_MOCK', false),

    /*
    |--------------------------------------------------------------------------
    | Recovery KEK derivation parameters (Argon2id)
    |--------------------------------------------------------------------------
    |
    | These parameters control the cost of deriving a Recovery KEK from a
    | 24-word BIP39 phrase. The defaults are interactive-grade (sub-second
    | on a modern laptop, multi-second on a phone — acceptable for the
    | once-per-recovery-session derivation).
    |
    | Increasing these values strengthens recovery against offline attack on
    | the wrapped DEKs but slows recovery for legitimate users. Do not change
    | after issuing recovery keys to users — the verifier hash stored on
    | bloxy_user_crypto is computed with the values that were active at
    | issuance time. (Verifier rotation requires re-issuing all recovery keys.)
    |
    */
    'recovery' => [
        'argon2id_time' => env('BLOXY_CRYPTO_ARGON2ID_TIME', 4),
        'argon2id_memory_kb' => env('BLOXY_CRYPTO_ARGON2ID_MEMORY_KB', 65536),
    ],
];
