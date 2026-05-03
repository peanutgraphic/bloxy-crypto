<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Tests\Feature\MockWrapTest;

use Bloxy\Crypto\Casts\EnvelopeEncrypted;
use Bloxy\Crypto\Mock\MockWrap;
use Illuminate\Database\Eloquent\Model;

class FakeMockModel extends Model
{
    protected $table = 'fake_mock_models';
    protected $guarded = [];
    public $timestamps = false;
    protected function casts(): array
    {
        return ['secret' => EnvelopeEncrypted::class];
    }
}

beforeEach(function () {
    \Illuminate\Support\Facades\Schema::create('fake_mock_models', function ($t) {
        $t->id();
        $t->text('secret')->nullable();
    });
});

it('produces a cast-compatible envelope', function () {
    $env = MockWrap::envelope('my secret value');
    $model = FakeMockModel::create(['secret' => $env]);

    expect(FakeMockModel::find($model->id)->secret)->toBe($env);
});

it('round-trips plaintext through wrap and unwrap', function () {
    $env = MockWrap::envelope('hello world');
    expect(MockWrap::unwrap($env))->toBe('hello world');
});

it('refuses to operate when mock mode is disabled', function () {
    config()->set('bloxy-crypto.mock', false);

    expect(fn () => MockWrap::envelope('x'))
        ->toThrow(\RuntimeException::class, 'mock is not enabled');
});
