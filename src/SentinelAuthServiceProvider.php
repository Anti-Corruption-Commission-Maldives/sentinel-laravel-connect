<?php

declare(strict_types=1);

namespace Sentinel\Auth;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Sentinel\Auth\Contracts\SentinelUserResolver;
use Sentinel\Auth\Resolvers\EloquentResolver;
use Sentinel\Auth\Resolvers\PlainResolver;

class SentinelAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/sentinel-auth.php', 'sentinel-auth');

        $this->app->bind(SentinelUserResolver::class, function ($app) {
            $resolver = config('sentinel-auth.resolver', 'plain');

            if ($resolver === 'plain') {
                return new PlainResolver;
            }

            if ($resolver === 'eloquent') {
                $model = config('sentinel-auth.user_model');
                $lookups = config('sentinel-auth.lookups', [
                    'office_emails' => 'office_email',
                    'emails' => 'email',
                ]);

                if (! $model) {
                    throw new \RuntimeException(
                        'sentinel-auth.user_model must be set when using the eloquent resolver.'
                    );
                }

                return new EloquentResolver($model, $lookups);
            }

            // Custom FQCN
            return $app->make($resolver);
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/sentinel-auth.php' => config_path('sentinel-auth.php'),
        ], 'sentinel-auth-config');

        Auth::extend('passport-token', function ($app, $name, $config) {
            return new PassportTokenGuard(
                request: $app['request'],
                sentinelAuthUrl: config('sentinel-auth.url'),
                resolver: $app->make(SentinelUserResolver::class),
            );
        });
    }
}
