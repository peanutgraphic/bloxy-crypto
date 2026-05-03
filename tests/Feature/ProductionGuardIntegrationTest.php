<?php

declare(strict_types=1);

namespace Bloxy\Crypto\Tests\Feature\ProductionGuardIntegrationTest;

use Bloxy\Crypto\BloxyCryptoServiceProvider;
use Illuminate\Config\Repository;
use Illuminate\Events\Dispatcher;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Foundation\Application;

/**
 * Integration test: confirms the guard is wired into the framework's
 * provider boot() lifecycle, not just present as a private reflectable
 * method on the provider class.
 *
 * Builds a real Illuminate\Foundation\Application (not a unit-test mock),
 * registers BloxyCryptoServiceProvider through the standard
 * $app->register() path, and then triggers $app->boot() — the same path
 * Laravel uses on every request and every Testbench setUp(). If the
 * guard is connected, $app->boot() throws RuntimeException.
 *
 * If a future refactor silently disconnects the guard from boot() while
 * leaving the method intact, the unit-level reflection tests in
 * ProductionGuardTest would still pass — this test would catch that
 * regression.
 *
 * Note: we use a hand-built Application rather than a Testbench Application
 * because Pest's Pest.php binds Bloxy\Crypto\Tests\TestCase to all of
 * tests/Feature, blocking the inline-child-TestCase pattern. The real
 * goal — exercising the framework's $app->boot() pipeline — is satisfied
 * by Illuminate\Foundation\Application directly.
 */
it('boot fails when env=production AND mock=true (real Application boot lifecycle)', function () {
    $app = new Application(__DIR__);
    $app['env'] = 'production';
    $app->detectEnvironment(fn () => 'production');

    // Bind the bare minimum services the provider's boot() touches.
    $app->instance('config', new Repository([
        'bloxy-crypto' => ['mock' => true, 'recovery' => []],
    ]));
    $app->instance('files', new Filesystem());
    $app->instance('events', new Dispatcher($app));
    // loadMigrationsFrom() resolves 'migrator' via the deferred migrator
    // service. We register a no-op stand-in so the call is harmless;
    // the guard fires before anything else in boot() that would care.
    $app->instance('migrator', new class {
        public function path($path): void {}
    });

    // Register through the framework's standard path, then trigger the
    // boot lifecycle the same way Laravel does on every request.
    $app->register(BloxyCryptoServiceProvider::class);
    $app->boot();
})->throws(\RuntimeException::class, 'only "local" and "testing" environments');
