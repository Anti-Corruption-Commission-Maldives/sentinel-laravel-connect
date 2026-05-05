<?php

declare(strict_types=1);

namespace Sentinel\Auth\Tests\Unit;

use Illuminate\Support\Facades\Auth;
use Sentinel\Auth\Contracts\SentinelUserResolver;
use Sentinel\Auth\PassportTokenGuard;
use Sentinel\Auth\Resolvers\EloquentResolver;
use Sentinel\Auth\Resolvers\PlainResolver;
use Sentinel\Auth\Tests\TestCase;

class SentinelAuthServiceProviderTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        // Only set cache — do NOT set sentinel-auth.* so package defaults apply
        $app['config']->set('cache.default', 'array');
    }

    // -------------------------------------------------------------------------
    // Resolver binding
    // -------------------------------------------------------------------------

    public function test_binds_plain_resolver_when_configured(): void
    {
        config(['sentinel-auth.resolver' => 'plain']);

        $resolver = $this->app->make(SentinelUserResolver::class);

        $this->assertInstanceOf(PlainResolver::class, $resolver);
    }

    public function test_binds_eloquent_resolver_when_configured_with_model(): void
    {
        config([
            'sentinel-auth.resolver' => 'eloquent',
            'sentinel-auth.user_model' => ResolverTestUser::class,
            'sentinel-auth.lookups' => ['email' => 'email'],
        ]);

        $resolver = $this->app->make(SentinelUserResolver::class);

        $this->assertInstanceOf(EloquentResolver::class, $resolver);
    }

    public function test_throws_when_eloquent_resolver_has_no_user_model(): void
    {
        config([
            'sentinel-auth.resolver' => 'eloquent',
            'sentinel-auth.user_model' => null,
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('sentinel-auth.user_model must be set');

        $this->app->make(SentinelUserResolver::class);
    }

    public function test_binds_custom_fqcn_resolver(): void
    {
        $custom = new class implements SentinelUserResolver
        {
            public function resolve(string $sub, object $token): mixed
            {
                return (object) ['id' => $sub, 'source' => 'custom'];
            }
        };

        // Bind the anonymous class first, then reference it by FQCN approach
        $this->app->bind(CustomTestResolver::class, fn () => new CustomTestResolver);
        config(['sentinel-auth.resolver' => CustomTestResolver::class]);

        $resolver = $this->app->make(SentinelUserResolver::class);

        $this->assertInstanceOf(CustomTestResolver::class, $resolver);
    }

    // -------------------------------------------------------------------------
    // Guard driver
    // -------------------------------------------------------------------------

    public function test_registers_passport_token_guard_driver(): void
    {
        config([
            'sentinel-auth.url' => 'http://auth.sentinel.test',
            'sentinel-auth.resolver' => 'plain',
            'auth.guards.api' => ['driver' => 'passport-token', 'provider' => 'users'],
            'auth.providers.users' => ['driver' => 'eloquent', 'model' => \stdClass::class],
        ]);

        $guard = Auth::guard('api');

        $this->assertInstanceOf(PassportTokenGuard::class, $guard);
    }

    // -------------------------------------------------------------------------
    // Config merging
    // -------------------------------------------------------------------------

    public function test_published_config_overrides_package_defaults(): void
    {
        config(['sentinel-auth.audience' => 'my-custom-app']);

        $this->assertSame('my-custom-app', config('sentinel-auth.audience'));
    }

    public function test_default_config_values_are_set(): void
    {
        $this->assertSame('sentinel-api', config('sentinel-auth.audience'));
        $this->assertSame(60, (int) config('sentinel-auth.cache_ttl'));
        $this->assertSame('plain', config('sentinel-auth.resolver'));
        $this->assertSame(
            ['official_email' => 'official_email', 'email' => 'email'],
            config('sentinel-auth.lookups'),
        );
    }
}

// Named class needed because anonymous classes cannot be used as FQCN config values
class CustomTestResolver implements SentinelUserResolver
{
    public function resolve(string $sub, object $token): mixed
    {
        return (object) ['id' => $sub, 'source' => 'custom'];
    }
}
