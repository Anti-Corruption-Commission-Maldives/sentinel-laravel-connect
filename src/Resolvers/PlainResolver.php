<?php

declare(strict_types=1);

namespace Sentinel\Auth\Resolvers;

use Sentinel\Auth\Contracts\SentinelUserResolver;

class PlainResolver implements SentinelUserResolver
{
    public function resolve(string $sub, object $token): object
    {
        return (object) ['id' => $sub];
    }
}
