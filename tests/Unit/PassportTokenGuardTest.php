<?php

declare(strict_types=1);

namespace Sentinel\Auth\Tests\Unit;

use Firebase\JWT\JWT;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Sentinel\Auth\Contracts\SentinelUserResolver;
use Sentinel\Auth\Tests\TestCase;

class PassportTokenGuardTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
        Http::preventStrayRequests();
    }

    // -------------------------------------------------------------------------
    // No token
    // -------------------------------------------------------------------------

    public function test_returns_null_when_no_bearer_token_present(): void
    {
        $guard = $this->makeGuard(token: null);

        $this->assertNull($guard->user());
    }

    // -------------------------------------------------------------------------
    // validate() must always be false — guard is read-only
    // -------------------------------------------------------------------------

    public function test_validate_always_returns_false(): void
    {
        $guard = $this->makeGuard(token: null);

        $this->assertFalse($guard->validate(['token' => 'anything']));
        $this->assertFalse($guard->validate([]));
    }

    // -------------------------------------------------------------------------
    // Happy path
    // -------------------------------------------------------------------------

    public function test_resolves_user_with_valid_token(): void
    {
        $token = $this->buildToken();
        $this->fakeJwks(static::$primaryKey);

        $user = $this->makeGuard($token)->user();

        $this->assertIsObject($user);
        $this->assertSame('user-sub-123', $user->id);
    }

    public function test_user_is_cached_and_jwks_fetched_only_once(): void
    {
        $token = $this->buildToken();
        $this->fakeJwks(static::$primaryKey);

        $guard = $this->makeGuard($token);
        $first = $guard->user();
        $second = $guard->user();

        $this->assertSame($first, $second);
        Http::assertSentCount(1);
    }

    public function test_trailing_slash_stripped_from_sentinel_url(): void
    {
        $token = $this->buildToken();

        Http::fake([
            'http://auth.sentinel.test/.well-known/jwks.json' => Http::response(
                $this->jwksResponse(static::$primaryKey)
            ),
        ]);

        $guard = $this->makeGuard($token, url: 'http://auth.sentinel.test/');
        $user = $guard->user();

        $this->assertNotNull($user);
    }

    // -------------------------------------------------------------------------
    // Malformed / bad format
    // -------------------------------------------------------------------------

    public function test_throws_when_token_is_not_a_jwt(): void
    {
        $this->expectException(AuthenticationException::class);

        $this->makeGuard('not-a-jwt-at-all')->user();
    }

    public function test_throws_when_token_has_only_two_segments(): void
    {
        $this->expectException(AuthenticationException::class);

        $this->makeGuard('header.payload')->user();
    }

    public function test_throws_when_token_is_random_base64(): void
    {
        $this->expectException(AuthenticationException::class);

        $this->makeGuard(base64_encode('garbage'))->user();
    }

    // -------------------------------------------------------------------------
    // Sub claim
    // -------------------------------------------------------------------------

    public function test_throws_when_sub_claim_is_missing(): void
    {
        $token = $this->buildToken(['sub' => null]);
        $this->fakeJwks(static::$primaryKey);

        $this->expectException(AuthenticationException::class);

        $this->makeGuard($token)->user();
    }

    public function test_throws_when_sub_claim_is_empty_string(): void
    {
        $token = $this->buildToken(['sub' => '']);
        $this->fakeJwks(static::$primaryKey);

        $this->expectException(AuthenticationException::class);

        $this->makeGuard($token)->user();
    }

    // -------------------------------------------------------------------------
    // Expiry / timing
    // -------------------------------------------------------------------------

    public function test_throws_when_token_is_expired(): void
    {
        // Expired 2 hours ago — beyond 60s leeway
        $token = $this->buildToken(['iat' => time() - 7200, 'exp' => -7200]);
        $this->fakeJwks(static::$primaryKey);

        $this->expectException(AuthenticationException::class);

        $this->makeGuard($token)->user();
    }

    public function test_throws_when_token_is_not_yet_valid(): void
    {
        // nbf 2 minutes in the future — beyond 60s leeway
        $token = $this->buildToken(['nbf' => time() + 120]);
        $this->fakeJwks(static::$primaryKey);

        $this->expectException(AuthenticationException::class);

        $this->makeGuard($token)->user();
    }

    public function test_accepts_token_within_leeway_window(): void
    {
        // iat=now-90, expiresIn=60 → exp=now-30 (expired 30s ago, within 60s leeway)
        $token = $this->buildToken(['iat' => time() - 90, 'exp' => 60]);
        $this->fakeJwks(static::$primaryKey);

        $user = $this->makeGuard($token)->user();

        $this->assertNotNull($user);
    }

    // -------------------------------------------------------------------------
    // Audience
    // -------------------------------------------------------------------------

    public function test_throws_when_audience_does_not_match_config(): void
    {
        $token = $this->buildToken(['aud' => 'wrong-audience']);
        $this->fakeJwks(static::$primaryKey);

        $this->expectException(AuthenticationException::class);

        $this->makeGuard($token)->user();
    }

    public function test_throws_when_audience_claim_is_missing(): void
    {
        $token = $this->buildToken(['aud' => null]);
        $this->fakeJwks(static::$primaryKey);

        $this->expectException(AuthenticationException::class);

        $this->makeGuard($token)->user();
    }

    public function test_accepts_audience_as_array_containing_configured_value(): void
    {
        $token = $this->buildToken(['aud' => ['test-app', 'other-app']]);
        $this->fakeJwks(static::$primaryKey);

        $user = $this->makeGuard($token)->user();

        $this->assertNotNull($user);
    }

    // -------------------------------------------------------------------------
    // Signature / key validation
    // -------------------------------------------------------------------------

    public function test_throws_when_signature_invalid_and_retry_also_fails(): void
    {
        // Token signed with secondary key, JWKS always returns primary
        $token = $this->buildToken(['keyPair' => static::$secondaryKey, 'kid' => 'secondary-kid']);

        Http::fake([
            'http://auth.sentinel.test/.well-known/jwks.json' => Http::response(
                $this->jwksResponse(static::$primaryKey)
            ),
        ]);

        $this->expectException(AuthenticationException::class);

        $this->makeGuard($token)->user();
    }

    public function test_retries_jwks_fetch_on_signature_failure_for_key_rotation(): void
    {
        // Token signed with secondary key
        $token = $this->buildToken(['keyPair' => static::$secondaryKey, 'kid' => 'secondary-kid']);

        Http::fake([
            'http://auth.sentinel.test/.well-known/jwks.json' => Http::sequence()
                ->push($this->jwksResponse(static::$primaryKey))   // first: wrong key (cached)
                ->push($this->jwksResponse(static::$secondaryKey)), // retry: correct key
        ]);

        $user = $this->makeGuard($token)->user();

        $this->assertNotNull($user);
        Http::assertSentCount(2);
    }

    public function test_jwks_is_cached_and_reused_across_requests(): void
    {
        $token1 = $this->buildToken(['sub' => 'user-1']);
        $token2 = $this->buildToken(['sub' => 'user-2']);
        $this->fakeJwks(static::$primaryKey);

        $this->makeGuard($token1)->user();
        $this->makeGuard($token2)->user();

        // Second request hits cache, not JWKS endpoint
        Http::assertSentCount(1);
    }

    // -------------------------------------------------------------------------
    // Algorithm attacks
    // -------------------------------------------------------------------------

    public function test_throws_when_alg_none_token_presented(): void
    {
        // Craft alg:none token manually
        $b64 = fn (string $data) => rtrim(strtr(base64_encode($data), '+/', '-_'), '=');

        $header = $b64('{"alg":"none","typ":"JWT"}');
        $payload = $b64(json_encode([
            'sub' => 'attacker',
            'aud' => 'test-app',
            'iat' => time(),
            'exp' => time() + 3600,
        ]));
        $noneToken = "{$header}.{$payload}.";

        $this->fakeJwks(static::$primaryKey);
        $this->expectException(AuthenticationException::class);

        $this->makeGuard($noneToken)->user();
    }

    public function test_throws_when_hs256_token_presented_to_rs256_guard(): void
    {
        $payload = [
            'sub' => 'attacker',
            'aud' => 'test-app',
            'iat' => time(),
            'exp' => time() + 3600,
        ];
        // firebase requires ≥256-bit (32-char) secret for HS256
        $hmacToken = JWT::encode($payload, str_repeat('x', 32), 'HS256', static::$primaryKey['kid']);

        Http::fake([
            'http://auth.sentinel.test/.well-known/jwks.json' => Http::sequence()
                ->push($this->jwksResponse(static::$primaryKey))
                ->push($this->jwksResponse(static::$primaryKey)),
        ]);

        $this->expectException(AuthenticationException::class);

        $this->makeGuard($hmacToken)->user();
    }

    public function test_throws_when_token_signed_with_completely_different_rsa_key(): void
    {
        $alien = static::generateKeyPair('alien-kid');
        $token = $this->buildToken(['keyPair' => $alien, 'kid' => static::$primaryKey['kid']]);

        // JWKS returns only primary key — alien key not registered
        Http::fake([
            'http://auth.sentinel.test/.well-known/jwks.json' => Http::sequence()
                ->push($this->jwksResponse(static::$primaryKey))
                ->push($this->jwksResponse(static::$primaryKey)),
        ]);

        $this->expectException(AuthenticationException::class);

        $this->makeGuard($token)->user();
    }

    // -------------------------------------------------------------------------
    // JWKS fetch failures
    // -------------------------------------------------------------------------

    public function test_throws_when_jwks_endpoint_returns_server_error(): void
    {
        Http::fake([
            'http://auth.sentinel.test/.well-known/jwks.json' => Http::response(null, 500),
        ]);

        $this->expectException(AuthenticationException::class);

        $this->makeGuard($this->buildToken())->user();
    }

    public function test_throws_when_jwks_endpoint_returns_404(): void
    {
        Http::fake([
            'http://auth.sentinel.test/.well-known/jwks.json' => Http::response(null, 404),
        ]);

        $this->expectException(AuthenticationException::class);

        $this->makeGuard($this->buildToken())->user();
    }

    public function test_throws_when_jwks_keys_array_is_empty(): void
    {
        Http::fake([
            'http://auth.sentinel.test/.well-known/jwks.json' => Http::response(['keys' => []]),
        ]);

        $this->expectException(AuthenticationException::class);

        $this->makeGuard($this->buildToken())->user();
    }

    public function test_throws_when_jwks_contains_no_rsa_keys(): void
    {
        Http::fake([
            'http://auth.sentinel.test/.well-known/jwks.json' => Http::response([
                'keys' => [
                    ['kty' => 'EC', 'kid' => 'ec-key', 'crv' => 'P-256', 'x' => 'abc', 'y' => 'def'],
                ],
            ]),
        ]);

        $this->expectException(AuthenticationException::class);

        $this->makeGuard($this->buildToken())->user();
    }

    public function test_skips_non_rsa_keys_and_uses_rsa_key(): void
    {
        $jwks = $this->jwksResponse(static::$primaryKey);
        // Inject an EC key before the RSA key
        array_unshift($jwks['keys'], [
            'kty' => 'EC', 'kid' => 'ec-key', 'crv' => 'P-256', 'x' => 'abc', 'y' => 'def',
        ]);

        Http::fake([
            'http://auth.sentinel.test/.well-known/jwks.json' => Http::response($jwks),
        ]);

        $token = $this->buildToken();
        $user = $this->makeGuard($token)->user();

        $this->assertNotNull($user);
    }

    // -------------------------------------------------------------------------
    // kid matching
    // -------------------------------------------------------------------------

    public function test_selects_correct_key_by_kid_when_multiple_keys_in_jwks(): void
    {
        // Token signed with secondary key
        $token = $this->buildToken(['keyPair' => static::$secondaryKey, 'kid' => 'secondary-kid']);

        // JWKS contains both keys
        $this->fakeJwks(static::$primaryKey, static::$secondaryKey);

        $user = $this->makeGuard($token)->user();

        $this->assertNotNull($user);
        Http::assertSentCount(1); // No retry needed
    }

    public function test_throws_when_token_kid_is_not_present_in_jwks(): void
    {
        // firebase does not fall back — unknown kid means strict rejection after retry
        $token = $this->buildToken(['kid' => 'unknown-kid']);

        Http::fake([
            'http://auth.sentinel.test/.well-known/jwks.json' => Http::sequence()
                ->push($this->jwksResponse(static::$primaryKey))
                ->push($this->jwksResponse(static::$primaryKey)),
        ]);

        $this->expectException(AuthenticationException::class);

        $this->makeGuard($token)->user();
    }

    // -------------------------------------------------------------------------
    // Resolver integration
    // -------------------------------------------------------------------------

    public function test_throws_when_resolver_throws_authentication_exception(): void
    {
        $resolver = new class implements SentinelUserResolver
        {
            public function resolve(string $sub, object $token): mixed
            {
                throw new AuthenticationException('User not found.');
            }
        };

        $token = $this->buildToken();
        $this->fakeJwks(static::$primaryKey);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('User not found.');

        $this->makeGuard($token, $resolver)->user();
    }

    public function test_wraps_generic_resolver_exception_as_authentication_exception(): void
    {
        $resolver = new class implements SentinelUserResolver
        {
            public function resolve(string $sub, object $token): mixed
            {
                throw new \RuntimeException('DB connection failed.');
            }
        };

        $token = $this->buildToken();
        $this->fakeJwks(static::$primaryKey);

        $this->expectException(AuthenticationException::class);

        $this->makeGuard($token, $resolver)->user();
    }

    public function test_resolver_receives_correct_sub_and_decoded_payload(): void
    {
        $captured = new \stdClass;
        $captured->sub = null;
        $captured->token = null;

        $resolver = new class($captured) implements SentinelUserResolver
        {
            public function __construct(private \stdClass $captured) {}

            public function resolve(string $sub, object $token): mixed
            {
                $this->captured->sub = $sub;
                $this->captured->token = $token;

                return (object) ['id' => $sub];
            }
        };

        $token = $this->buildToken(['sub' => 'specific-user-id', 'extra' => ['role' => 'admin']]);
        $this->fakeJwks(static::$primaryKey);

        $this->makeGuard($token, $resolver)->user();

        $this->assertSame('specific-user-id', $captured->sub);
        $this->assertSame('specific-user-id', $captured->token->sub);
        $this->assertSame('admin', $captured->token->role);
    }
}
