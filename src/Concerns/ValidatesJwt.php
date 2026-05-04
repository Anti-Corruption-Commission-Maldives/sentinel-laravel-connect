<?php

declare(strict_types=1);

namespace Sentinel\Auth\Concerns;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

trait ValidatesJwt
{
    use LogsAuthEvents;

    private function cacheKey(): string
    {
        return 'sentinel_jwks_'.md5($this->sentinelAuthUrl);
    }

    private function fetchJwks(): array
    {
        $url = $this->sentinelAuthUrl.'/.well-known/jwks.json';
        $this->debug('jwks.fetch.start', ['url' => $url]);

        $response = Http::timeout(10)->get($url);

        if ($response->failed()) {
            $this->debug('jwks.fetch.failed', ['url' => $url, 'status' => $response->status()]);
            throw new \RuntimeException('Failed to fetch JWKS from Sentinel.');
        }

        $keys = array_filter(
            $response->json('keys') ?? [],
            fn ($key) => ($key['kty'] ?? '') === 'RSA'
        );

        if (empty($keys)) {
            $this->debug('jwks.fetch.no_rsa_keys', ['url' => $url]);
            throw new \RuntimeException('No RSA keys found in JWKS response.');
        }

        $this->debug('jwks.fetch.complete', [
            'url' => $url,
            'rsa_key_count' => count($keys),
            'kids' => array_values(array_map(fn ($k) => $k['kid'] ?? null, $keys)),
        ]);

        return ['keys' => array_values($keys)];
    }

    private function getCachedJwks(): array
    {
        $key = $this->cacheKey();
        $hit = Cache::has($key);
        $this->debug('jwks.cache', ['hit' => $hit, 'key' => $key]);

        return Cache::remember(
            $key,
            now()->addMinutes((int) config('sentinel-auth.cache_ttl', 60)),
            fn () => $this->fetchJwks()
        );
    }

    protected function decodeToken(string $tokenString): object
    {
        JWT::$leeway = 60;

        $audience = config('sentinel-auth.audience', 'sentinel-api');

        $this->debug('decode.start', [
            'token' => $this->redactToken($tokenString),
            'expected_audience' => $audience,
        ]);

        $jwks = $this->getCachedJwks();

        try {
            $decoded = JWT::decode($tokenString, JWK::parseKeySet($jwks));
        } catch (SignatureInvalidException|\UnexpectedValueException $e) {
            $this->debug('decode.retry', [
                'reason' => $e::class,
                'message' => $e->getMessage(),
            ]);

            // Signature invalid or kid not in cached JWKS — may be stale key. Bust and retry once.
            Cache::forget($this->cacheKey());
            $jwks = $this->getCachedJwks();
            $decoded = JWT::decode($tokenString, JWK::parseKeySet($jwks));
        }

        // firebase/php-jwt validates exp/nbf/iat but not aud — check manually
        $aud = isset($decoded->aud) ? (array) $decoded->aud : [];
        if (! in_array($audience, $aud, true)) {
            $this->debug('decode.audience_mismatch', [
                'expected' => $audience,
                'received' => $aud,
            ]);
            throw new AuthenticationException('Token audience mismatch.');
        }

        $this->debug('decode.success', [
            'sub' => $this->redactId(isset($decoded->sub) ? (string) $decoded->sub : null),
            'audience' => $audience,
            'claims' => array_keys((array) $decoded),
        ]);

        return $decoded;
    }
}
