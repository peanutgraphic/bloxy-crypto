<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Tests\Feature\EnvelopeEncryptedTest;

use Bloxy\Crypto\Casts\EnvelopeEncrypted;
use Bloxy\Crypto\Exceptions\PlaintextRejectedException;
use Illuminate\Database\Eloquent\Model;

class FakeEnvelopeModel extends Model
{
    protected $table = 'fake_envelope_models';
    protected $guarded = [];
    public $timestamps = false;
    protected function casts(): array
    {
        return ['secret' => EnvelopeEncrypted::class];
    }
}

beforeEach(function () {
    \Illuminate\Support\Facades\Schema::create('fake_envelope_models', function ($t) {
        $t->id();
        $t->text('secret')->nullable();
    });
});

it('round-trips a valid envelope through the cast', function () {
    $envelope = [
        'v' => 1,
        'nonce' => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        'ciphertext' => 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
        'wrapped_dek' => 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
    ];

    $model = FakeEnvelopeModel::create(['secret' => $envelope]);
    $reloaded = FakeEnvelopeModel::find($model->id);

    expect($reloaded->secret)->toBe($envelope);
});

it('stores envelope as JSON in the DB column', function () {
    $envelope = ['v' => 1, 'nonce' => 'A', 'ciphertext' => 'B', 'wrapped_dek' => 'C'];
    $model = FakeEnvelopeModel::create(['secret' => $envelope]);

    $raw = \Illuminate\Support\Facades\DB::table('fake_envelope_models')->find($model->id)->secret;

    expect($raw)->toBeString();
    expect(json_decode($raw, true))->toBe($envelope);
});

it('returns null for a null column', function () {
    $model = FakeEnvelopeModel::create(['secret' => null]);
    expect(FakeEnvelopeModel::find($model->id)->secret)->toBeNull();
});

it('rejects a plaintext string with PlaintextRejectedException', function () {
    expect(fn () => FakeEnvelopeModel::create(['secret' => 'my-ssn-123-45-6789']))
        ->toThrow(PlaintextRejectedException::class);
});

it('rejects an array missing required envelope keys', function () {
    expect(fn () => FakeEnvelopeModel::create(['secret' => ['v' => 1, 'nonce' => 'A']]))
        ->toThrow(PlaintextRejectedException::class);
});

it('rejects an envelope with an unsupported version', function () {
    expect(fn () => FakeEnvelopeModel::create(['secret' => [
        'v' => 999, 'nonce' => 'A', 'ciphertext' => 'B', 'wrapped_dek' => 'C',
    ]]))->toThrow(PlaintextRejectedException::class);
});
