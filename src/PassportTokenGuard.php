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
            $this->debug('guard.no_bearer_token');

            return null;
        }

        $this->debug('guard.start', [
            'token' => $this->redactToken($tokenString),
            'resolver' => $this->resolver::class,
        ]);

        try {
            $decoded = $this->decodeToken($tokenString);
            $sub = (string) ($decoded->sub ?? '');

            if ($sub === '') {
                $this->debug('guard.missing_sub');
                throw new AuthenticationException('Token missing sub claim.');
            }

            $this->debug('guard.resolver.calling', ['sub' => $this->redactId($sub)]);
            $this->user = $this->resolver->resolve($sub, $decoded);
            $this->debug('guard.resolver.success', [
                'user_class' => is_object($this->user) ? $this->user::class : gettype($this->user),
            ]);

            return $this->user;

        } catch (AuthenticationException $e) {
            $this->debug('guard.failure', [
                'exception' => $e::class,
                'message' => $e->getMessage(),
            ]);
            throw $e;
        } catch (ExpiredException) {
            $this->debug('guard.failure', ['exception' => ExpiredException::class]);
            throw new AuthenticationException('Token has expired.');
        } catch (SignatureInvalidException) {
            $this->debug('guard.failure', ['exception' => SignatureInvalidException::class]);
            throw new AuthenticationException('Token signature invalid.');
        } catch (\Throwable $e) {
            $this->debug('guard.failure', [
                'exception' => $e::class,
                'message' => $e->getMessage(),
            ]);
            throw new AuthenticationException('Authentication failed.');
        }
    }

    public function validate(array $credentials = []): bool
    {
        return false;
    }
}
