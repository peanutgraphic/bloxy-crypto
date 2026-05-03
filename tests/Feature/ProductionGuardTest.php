<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Tests\Feature\ProductionGuardTest;

use Bloxy\Crypto\BloxyCryptoServiceProvider;
use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;

function invokeGuard(string $env, bool $mock): \Closure
{
    $app = new Application(__DIR__);
    $app['env'] = $env;
    $app->instance('config', new Repository([
        'bloxy-crypto' => ['mock' => $mock, 'recovery' => []],
    ]));

    $provider = new BloxyCryptoServiceProvider($app);

    $reflection = new \ReflectionClass($provider);
    $method = $reflection->getMethod('guardAgainstMockOutsideDev');
    $method->setAccessible(true);

    return fn () => $method->invoke($provider);
}

it('refuses to boot outside dev environments with mock=true (production)', function () {
    expect(invokeGuard('production', true))
        ->toThrow(\RuntimeException::class, 'only "local" and "testing" environments');
});

it('refuses to boot outside dev environments with mock=true (staging)', function () {
    expect(invokeGuard('staging', true))
        ->toThrow(\RuntimeException::class, 'only "local" and "testing" environments');
});

it('boots cleanly in production with mock=false', function () {
    expect(invokeGuard('production', false))->not->toThrow(\Throwable::class);
});

it('boots cleanly in local with mock=true (allowlist member)', function () {
    expect(invokeGuard('local', true))->not->toThrow(\Throwable::class);
});

it('boots cleanly in testing with mock=true (allowlist member)', function () {
    expect(invokeGuard('testing', true))->not->toThrow(\Throwable::class);
});
