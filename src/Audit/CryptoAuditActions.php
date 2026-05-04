<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Audit;

/**
 * Canonical audit-log action strings for crypto-related operations consumers
 * may want to record. These constants exist for consumer reference — the
 * bloxy-crypto package itself does not emit audit rows for rewrap, since
 * rewrap is a client-side operation. Consumers (e.g., Tracy) reference these
 * constants when emitting their own audit rows from server-side rewrap
 * handlers.
 */
final class CryptoAuditActions
{
    public const REWRAP_BATCH_START = 'CRYPTO_REWRAP_BATCH_START';
    public const REWRAP_RECORD = 'CRYPTO_REWRAP_RECORD';
    public const REWRAP_BATCH_FAILED = 'CRYPTO_REWRAP_BATCH_FAILED';
}
