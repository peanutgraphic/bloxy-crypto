<?php

declare(strict_types=1);

use Bloxy\Crypto\Audit\CryptoAuditActions;

it('exposes stable rewrap audit action strings', function () {
    expect(CryptoAuditActions::REWRAP_BATCH_START)->toBe('CRYPTO_REWRAP_BATCH_START');
    expect(CryptoAuditActions::REWRAP_RECORD)->toBe('CRYPTO_REWRAP_RECORD');
    expect(CryptoAuditActions::REWRAP_BATCH_FAILED)->toBe('CRYPTO_REWRAP_BATCH_FAILED');
});
