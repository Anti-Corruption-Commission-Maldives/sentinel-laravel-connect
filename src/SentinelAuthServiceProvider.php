<?php

declare(strict_types=1);

namespace Sentinel\Auth;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
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

        $this->app->bind(SentinelUserResolver::class, function (Application $app) {
            $resolver = config('sentinel-auth.resolver', 'plain');

            if ($resolver === 'plain') {
                return new PlainResolver;
            }

            if ($resolver === 'eloquent') {
                $model = config('sentinel-auth.user_model');

                if (! is_string($model) || ! is_subclass_of($model, Model::class)) {
                    throw new \RuntimeException(
                        'sentinel-auth.user_model must be set to an Eloquent model class when using the eloquent resolver.'
                    );
                }

                $lookups = config('sentinel-auth.lookups');
                $lookupMap = [];
                if (is_array($lookups)) {
                    foreach ($lookups as $claim => $column) {
                        if (is_string($claim) && is_string($column)) {
                            $lookupMap[$claim] = $column;
                        }
                    }
                }

                return $lookupMap === []
                    ? new EloquentResolver($model)
                    : new EloquentResolver($model, $lookupMap);
            }

            // Custom FQCN
            if (! is_string($resolver)) {
                throw new \RuntimeException('sentinel-auth.resolver must be a string.');
            }

            return $app->make($resolver);
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/sentinel-auth.php' => config_path('sentinel-auth.php'),
        ], 'sentinel-auth-config');

        Auth::extend('passport-token', function (Application $app) {
            $url = config('sentinel-auth.url');

            return new PassportTokenGuard(
                request: $app->make(Request::class),
                sentinelAuthUrl: is_string($url) ? $url : '',
                resolver: $app->make(SentinelUserResolver::class),
            );
        });
    }
}
