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

    private bool $resolving = false;

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
        if ($this->user !== null) {
            return $this->user;
        }

        // Guard against re-entrancy: debug logging may pass through a log
        // pipeline (Telescope, Monolog processors) that resolves the auth
        // user, calling back into user() before $this->user is cached.
        if ($this->resolving) {
            return null;
        }

        $tokenString = $this->request->bearerToken();
        if (! $tokenString) {
            $this->debug('guard.no_bearer_token');

            return null;
        }

        $this->resolving = true;

        try {
            $this->debug('guard.start', [
                'token' => $this->redactToken($tokenString),
                'resolver' => $this->resolver::class,
            ]);

            $decoded = $this->decodeToken($tokenString);
            $rawSub = $decoded->sub ?? '';
            $sub = is_scalar($rawSub) ? (string) $rawSub : '';

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
        } finally {
            $this->resolving = false;
        }
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function validate(array $credentials = []): bool
    {
        return false;
    }
}
