<?php

declare(strict_types=1);

namespace Sentinel\Auth\Tests;

use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use Sentinel\Auth\Contracts\SentinelUserResolver;
use Sentinel\Auth\PassportTokenGuard;
use Sentinel\Auth\Resolvers\PlainResolver;
use Sentinel\Auth\SentinelAuthServiceProvider;

abstract class TestCase extends OrchestraTestCase
{
    protected static array $primaryKey = [];

    protected static array $secondaryKey = [];

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        static::$primaryKey = static::generateKeyPair('primary-kid');
        static::$secondaryKey = static::generateKeyPair('secondary-kid');
    }

    protected static function generateKeyPair(string $kid): array
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($resource, $privatePem);
        $details = openssl_pkey_get_details($resource);

        return [
            'kid' => $kid,
            'private_pem' => $privatePem,
            'public_pem' => $details['key'],
            'n' => rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '='),
            'e' => rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '='),
        ];
    }

    protected function getPackageProviders($app): array
    {
        return [SentinelAuthServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('sentinel-auth.url', 'http://auth.sentinel.test');
        $app['config']->set('sentinel-auth.audience', 'test-app');
        $app['config']->set('sentinel-auth.cache_ttl', 60);
        $app['config']->set('sentinel-auth.resolver', 'plain');
        $app['config']->set('cache.default', 'array');
    }

    /**
     * Build a signed RS256 JWT string.
     *
     * Pass null as a claim value to omit it from the payload entirely.
     */
    protected function buildToken(array $options = []): string
    {
        $keyPair = $options['keyPair'] ?? static::$primaryKey;
        $kid = $options['kid'] ?? $keyPair['kid'];
        $issuedAt = $options['iat'] ?? time();
        $expiresIn = $options['exp'] ?? 3600;

        $payload = [
            'sub' => $options['sub'] ?? 'user-sub-123',
            'aud' => $options['aud'] ?? 'test-app',
            'iat' => $issuedAt,
            'exp' => $issuedAt + $expiresIn,
        ];

        if (array_key_exists('nbf', $options)) {
            $payload['nbf'] = $options['nbf'];
        }

        // Allow tests to remove standard claims by passing null
        foreach (['sub', 'aud', 'iat', 'exp'] as $claim) {
            if (array_key_exists($claim, $options) && $options[$claim] === null) {
                unset($payload[$claim]);
            }
        }

        if (! empty($options['extra'])) {
            $payload = array_merge($payload, $options['extra']);
        }

        return JWT::encode($payload, $keyPair['private_pem'], 'RS256', $kid);
    }

    /**
     * Build a JWKS response body for one or more key pairs.
     */
    protected function jwksResponse(array ...$keyPairs): array
    {
        $keys = array_map(fn ($kp) => [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => $kp['kid'],
            'n' => $kp['n'],
            'e' => $kp['e'],
        ], $keyPairs);

        return ['keys' => $keys];
    }

    protected function makeGuard(
        ?string $token = null,
        ?SentinelUserResolver $resolver = null,
        string $url = 'http://auth.sentinel.test',
    ): PassportTokenGuard {
        $request = Request::create('/api/test', 'GET');

        if ($token !== null) {
            $request->headers->set('Authorization', "Bearer {$token}");
        }

        return new PassportTokenGuard(
            request: $request,
            sentinelAuthUrl: $url,
            resolver: $resolver ?? new PlainResolver,
        );
    }

    protected function fakeJwks(array ...$keyPairs): void
    {
        Http::fake([
            'http://auth.sentinel.test/.well-known/jwks.json' => Http::response(
                $this->jwksResponse(...$keyPairs)
            ),
        ]);
    }
}
