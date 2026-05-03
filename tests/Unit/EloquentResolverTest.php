<?php

declare(strict_types=1);

namespace Sentinel\Auth\Tests\Unit;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Sentinel\Auth\Resolvers\EloquentResolver;
use Sentinel\Auth\Tests\TestCase;

// Minimal in-memory model used only by these tests
class ResolverTestUser extends Model
{
    protected $table = 'resolver_test_users';

    protected $guarded = [];
}

class EloquentResolverTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('resolver_test_users', function (Blueprint $table) {
            $table->id();
            $table->string('auth_id')->nullable()->unique();
            $table->string('employee_id')->nullable()->unique();
            $table->timestamps();
        });
    }

    protected function tearDown(): void
    {
        Schema::dropIfExists('resolver_test_users');
        parent::tearDown();
    }

    public function test_returns_user_found_by_default_auth_id_column(): void
    {
        ResolverTestUser::create(['auth_id' => 'sentinel-sub-001']);

        $resolver = new EloquentResolver(ResolverTestUser::class);
        $user = $resolver->resolve('sentinel-sub-001', (object) []);

        $this->assertInstanceOf(ResolverTestUser::class, $user);
        $this->assertSame('sentinel-sub-001', $user->auth_id);
    }

    public function test_returns_user_found_by_custom_column(): void
    {
        ResolverTestUser::create(['employee_id' => 'EMP-999']);

        $resolver = new EloquentResolver(ResolverTestUser::class, 'employee_id');
        $user = $resolver->resolve('EMP-999', (object) []);

        $this->assertInstanceOf(ResolverTestUser::class, $user);
        $this->assertSame('EMP-999', $user->employee_id);
    }

    public function test_throws_when_user_not_found(): void
    {
        $resolver = new EloquentResolver(ResolverTestUser::class);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('User not found.');

        $resolver->resolve('non-existent-sub', (object) []);
    }

    public function test_throws_even_when_other_users_exist(): void
    {
        ResolverTestUser::create(['auth_id' => 'real-user']);

        $resolver = new EloquentResolver(ResolverTestUser::class);

        $this->expectException(AuthenticationException::class);

        $resolver->resolve('different-sub', (object) []);
    }

    public function test_uses_auth_id_as_default_column(): void
    {
        ResolverTestUser::create(['auth_id' => 'default-col-test']);

        // No second argument — should default to auth_id
        $resolver = new EloquentResolver(ResolverTestUser::class);
        $user = $resolver->resolve('default-col-test', (object) []);

        $this->assertSame('default-col-test', $user->auth_id);
    }

    public function test_token_payload_passed_but_not_used_for_lookup(): void
    {
        ResolverTestUser::create(['auth_id' => 'user-xyz']);

        $resolver = new EloquentResolver(ResolverTestUser::class);

        // Token has a different email — resolver must only use sub/column, not token claims
        $decoded = (object) ['sub' => 'user-xyz', 'email' => 'other@example.com'];
        $user = $resolver->resolve('user-xyz', $decoded);

        $this->assertSame('user-xyz', $user->auth_id);
    }
}
