<?php

declare(strict_types=1);

namespace Sentinel\Auth\Contracts;

interface SentinelUserResolver
{
    /**
     * Resolve a local user from a verified JWT payload.
     *
     * @param  string  $sub  The subject claim from the token.
     * @param  object  $token  The full decoded JWT payload (stdClass).
     *
     * MUST throw AuthenticationException if the user cannot be resolved.
     */
    public function resolve(string $sub, object $token): mixed;
}
