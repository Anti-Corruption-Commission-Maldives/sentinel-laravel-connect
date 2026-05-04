<?php

declare(strict_types=1);

namespace Sentinel\Auth\Resolvers;

use Sentinel\Auth\Contracts\SentinelUserResolver;

class PlainResolver implements SentinelUserResolver
{
    public function resolve(string $sub, object $token): object
    {
        return (object) [
            'id' => $sub,
            'official_email' => $this->stringClaim($token, 'official_email'),
            'email' => $this->stringClaim($token, 'email'),
        ];
    }

    private function stringClaim(object $token, string $claim): ?string
    {
        $value = $token->{$claim} ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }
}
