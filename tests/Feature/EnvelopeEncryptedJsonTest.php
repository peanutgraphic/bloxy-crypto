<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Tests\Feature\EnvelopeEncryptedJsonTest;

use Bloxy\Crypto\Casts\EnvelopeEncryptedJson;
use Bloxy\Crypto\Exceptions\PlaintextRejectedException;
use Illuminate\Database\Eloquent\Model;

class FakeJsonbModel extends Model
{
    protected $table = 'fake_jsonb_models';
    protected $guarded = [];
    public $timestamps = false;
    protected function casts(): array
    {
        return ['fields' => EnvelopeEncryptedJson::class];
    }
}

beforeEach(function () {
    \Illuminate\Support\Facades\Schema::create('fake_jsonb_models', function ($t) {
        $t->id();
        $t->json('fields')->nullable();
    });
});

function envelope(string $tag): array
{
    return ['v' => 1, 'nonce' => "n-$tag", 'ciphertext' => "c-$tag", 'wrapped_dek' => "w-$tag"];
}

it('round-trips a map-of-envelopes through the cast', function () {
    $value = ['ssn' => envelope('ssn'), 'dob' => envelope('dob')];

    $model = FakeJsonbModel::create(['fields' => $value]);
    expect(FakeJsonbModel::find($model->id)->fields)->toBe($value);
});

it('rejects a value where any entry is a plaintext string', function () {
    $value = ['ssn' => envelope('ssn'), 'dob' => '1970-01-01'];

    expect(fn () => FakeJsonbModel::create(['fields' => $value]))
        ->toThrow(PlaintextRejectedException::class);
});

it('returns null for a null column', function () {
    $model = FakeJsonbModel::create(['fields' => null]);
    expect(FakeJsonbModel::find($model->id)->fields)->toBeNull();
});

it('accepts an empty map', function () {
    $model = FakeJsonbModel::create(['fields' => []]);
    expect(FakeJsonbModel::find($model->id)->fields)->toBe([]);
});
