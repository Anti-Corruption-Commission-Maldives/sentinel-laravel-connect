<?php

declare(strict_types=1);

namespace Sentinel\Auth\Concerns;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

trait ValidatesJwt
{
    private function cacheKey(): string
    {
        return 'sentinel_jwks_'.md5($this->sentinelAuthUrl);
    }

    /**
     * @throws ConnectionException
     */
    private function fetchJwks(): array
    {
        $response = Http::timeout(10)->get($this->sentinelAuthUrl.'/.well-known/jwks.json');

        if ($response->failed()) {
            throw new \RuntimeException('Failed to fetch JWKS from Sentinel.');
        }

        $keys = array_filter(
            $response->json('keys') ?? [],
            fn ($key) => ($key['kty'] ?? '') === 'RSA'
        );

        if (empty($keys)) {
            throw new \RuntimeException('No RSA keys found in JWKS response.');
        }

        return ['keys' => array_values($keys)];
    }

    private function getCachedJwks(): array
    {
        return Cache::remember(
            $this->cacheKey(),
            now()->addMinutes((int) config('sentinel-auth.cache_ttl', 60)),
            fn () => $this->fetchJwks()
        );
    }

    protected function decodeToken(string $tokenString): object
    {
        JWT::$leeway = 60;

        $audience = config('sentinel-auth.audience', 'sentinel-api');

        $jwks = $this->getCachedJwks();

        try {
            $decoded = JWT::decode($tokenString, JWK::parseKeySet($jwks));
        } catch (SignatureInvalidException|\UnexpectedValueException $e) {
            // Signature invalid or kid not in cached JWKS — may be stale key. Bust and retry once.
            Cache::forget($this->cacheKey());
            $jwks = $this->getCachedJwks();
            $decoded = JWT::decode($tokenString, JWK::parseKeySet($jwks));
        }

        // firebase/php-jwt validates exp/nbf/iat but not aud — check manually
        $aud = isset($decoded->aud) ? (array) $decoded->aud : [];
        if (! in_array($audience, $aud, true)) {
            throw new AuthenticationException('Token audience mismatch.');
        }

        return $decoded;
    }
}
