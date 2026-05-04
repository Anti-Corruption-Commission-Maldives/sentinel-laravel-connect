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
            $table->string('official_email')->nullable()->unique();
            $table->string('email')->nullable()->unique();
            $table->string('employee_id')->nullable()->unique();
            $table->timestamps();
        });
    }

    protected function tearDown(): void
    {
        Schema::dropIfExists('resolver_test_users');
        parent::tearDown();
    }

    public function test_resolves_user_by_official_email_first(): void
    {
        ResolverTestUser::create([
            'official_email' => 'work@acme.com',
            'email' => 'unrelated@home.com',
        ]);

        $token = (object) [
            'official_email' => 'work@acme.com',
            'email' => 'someone-else@home.com',
        ];

        $resolver = new EloquentResolver(ResolverTestUser::class);
        $user = $resolver->resolve('ignored-sub', $token);

        $this->assertSame('work@acme.com', $user->official_email);
    }

    public function test_falls_back_to_email_when_official_email_lookup_fails(): void
    {
        ResolverTestUser::create([
            'official_email' => null,
            'email' => 'personal@home.com',
        ]);

        $token = (object) [
            'official_email' => 'no-such-office@acme.com',
            'email' => 'personal@home.com',
        ];

        $resolver = new EloquentResolver(ResolverTestUser::class);
        $user = $resolver->resolve('ignored-sub', $token);

        $this->assertSame('personal@home.com', $user->email);
    }

    public function test_skips_lookup_when_claim_missing(): void
    {
        ResolverTestUser::create(['email' => 'only-personal@home.com']);

        // No official_email claim — must skip directly to email lookup
        $token = (object) ['email' => 'only-personal@home.com'];

        $resolver = new EloquentResolver(ResolverTestUser::class);
        $user = $resolver->resolve('ignored-sub', $token);

        $this->assertSame('only-personal@home.com', $user->email);
    }

    public function test_skips_lookup_when_claim_is_empty_string(): void
    {
        ResolverTestUser::create(['email' => 'fallback@home.com']);

        $token = (object) ['official_email' => '', 'email' => 'fallback@home.com'];

        $resolver = new EloquentResolver(ResolverTestUser::class);
        $user = $resolver->resolve('ignored-sub', $token);

        $this->assertSame('fallback@home.com', $user->email);
    }

    public function test_skips_lookup_when_claim_is_null(): void
    {
        ResolverTestUser::create(['email' => 'fallback@home.com']);

        // Token has both claims, official_email is explicitly null (matches real Sentinel tokens)
        $token = (object) ['official_email' => null, 'email' => 'fallback@home.com'];

        $resolver = new EloquentResolver(ResolverTestUser::class);
        $user = $resolver->resolve('ignored-sub', $token);

        $this->assertSame('fallback@home.com', $user->email);
    }

    public function test_throws_when_no_lookup_matches(): void
    {
        ResolverTestUser::create([
            'official_email' => 'someone@acme.com',
            'email' => 'someone@home.com',
        ]);

        $token = (object) [
            'official_email' => 'missing@acme.com',
            'email' => 'missing@home.com',
        ];

        $resolver = new EloquentResolver(ResolverTestUser::class);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('User not found.');

        $resolver->resolve('ignored-sub', $token);
    }

    public function test_throws_when_token_has_no_relevant_claims(): void
    {
        ResolverTestUser::create(['email' => 'real@home.com']);

        $resolver = new EloquentResolver(ResolverTestUser::class);

        $this->expectException(AuthenticationException::class);

        $resolver->resolve('ignored-sub', (object) ['unrelated' => 'value']);
    }

    public function test_custom_lookup_chain_is_respected(): void
    {
        ResolverTestUser::create(['employee_id' => 'EMP-007']);

        $resolver = new EloquentResolver(
            ResolverTestUser::class,
            ['employee_id_claim' => 'employee_id'],
        );

        $token = (object) ['employee_id_claim' => 'EMP-007'];
        $user = $resolver->resolve('ignored-sub', $token);

        $this->assertSame('EMP-007', $user->employee_id);
    }

    public function test_does_not_use_sub_for_lookup(): void
    {
        // User exists with official_email matching what would be sub-as-official-email
        ResolverTestUser::create(['official_email' => 'sub-value@acme.com']);

        $resolver = new EloquentResolver(ResolverTestUser::class);

        // Token has no email claims — sub alone must NOT be used as a lookup value
        $token = (object) [];

        $this->expectException(AuthenticationException::class);

        $resolver->resolve('sub-value@acme.com', $token);
    }
}
