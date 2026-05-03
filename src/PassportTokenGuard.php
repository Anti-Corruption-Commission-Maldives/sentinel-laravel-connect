<?php

declare(strict_types=1);

namespace Sentinel\Auth;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Sentinel\Auth\Concerns\ValidatesJwt;
use Sentinel\Auth\Contracts\SentinelUserResolver;

class PassportTokenGuard implements Guard
{
    use GuardHelpers, ValidatesJwt;

    protected string $sentinelAuthUrl;

    private SentinelUserResolver $resolver;

    public function __construct(
        protected Request $request,
        string $sentinelAuthUrl,
        SentinelUserResolver $resolver
    ) {
        $this->sentinelAuthUrl = rtrim($sentinelAuthUrl, '/');
        $this->resolver = $resolver;
    }

    public function user(): mixed
    {
        if ($this->user) {
            return $this->user;
        }

        $tokenString = $this->request->bearerToken();
        if (! $tokenString) {
            return null;
        }

        try {
            $decoded = $this->decodeToken($tokenString);
            $sub = (string) ($decoded->sub ?? '');

            if ($sub === '') {
                throw new AuthenticationException('Token missing sub claim.');
            }

            $this->user = $this->resolver->resolve($sub, $decoded);

            return $this->user;

        } catch (AuthenticationException $e) {
            throw $e;
        } catch (ExpiredException) {
            throw new AuthenticationException('Token has expired.');
        } catch (SignatureInvalidException) {
            throw new AuthenticationException('Token signature invalid.');
        } catch (\Throwable) {
            throw new AuthenticationException('Authentication failed.');
        }
    }

    public function validate(array $credentials = []): bool
    {
        return false;
    }
}
