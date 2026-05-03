<?php

declare(strict_types=1);

namespace Bloxy\Crypto;

use Illuminate\Support\ServiceProvider;

class BloxyCryptoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/bloxy-crypto.php',
            'bloxy-crypto'
        );
    }

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        $this->guardAgainstMockOutsideDev();

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/bloxy-crypto.php' => config_path('bloxy-crypto.php'),
            ], 'bloxy-crypto-config');

            $this->publishes([
                __DIR__ . '/../database/migrations' => database_path('migrations'),
            ], 'bloxy-crypto-migrations');
        }
    }

    private function guardAgainstMockOutsideDev(): void
    {
        if ($this->app['config']->get('bloxy-crypto.mock', false) !== true) {
            return;
        }

        if (! $this->app->environment(['local', 'testing'])) {
            throw new \RuntimeException(
                'BLOXY_CRYPTO_MOCK is enabled in environment "'
                . $this->app->environment()
                . '" — only "local" and "testing" environments may run with MOCK mode. '
                . 'MOCK mode produces envelope-shaped values with NO real protection. '
                . 'Set BLOXY_CRYPTO_MOCK=false (or unset) and redeploy.'
            );
        }
    }
}
