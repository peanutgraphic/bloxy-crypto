<?php

declare(strict_types=1);

it('registers the bloxy-crypto config namespace', function () {
    $tags = $this->app['config']->get('bloxy-crypto');

    expect($tags)->toBeArray();
    expect($tags)->toHaveKey('mock');
    expect($tags)->toHaveKey('recovery');
});

it('registers the bloxy-crypto-config publish tag', function () {
    $paths = \Illuminate\Support\ServiceProvider::pathsToPublish(
        \Bloxy\Crypto\BloxyCryptoServiceProvider::class,
        'bloxy-crypto-config'
    );
    expect($paths)->toBeArray()->not->toBeEmpty();
});

it('registers the bloxy-crypto-migrations publish tag', function () {
    $paths = \Illuminate\Support\ServiceProvider::pathsToPublish(
        \Bloxy\Crypto\BloxyCryptoServiceProvider::class,
        'bloxy-crypto-migrations'
    );
    expect($paths)->toBeArray()->not->toBeEmpty();
});

it('loads the wrapped_deks migration', function () {
    expect(\Illuminate\Support\Facades\Schema::hasTable('wrapped_deks'))->toBeTrue();
});
