<?php

declare(strict_types=1);

return [
    'url' => env('SENTINEL_AUTH_URL'),
    'audience' => env('SENTINEL_AUTH_AUDIENCE', 'sentinel-api'),
    'cache_ttl' => env('SENTINEL_AUTH_CACHE_TTL', 60), // minutes

    /*
    |--------------------------------------------------------------------------
    | User Resolver
    |--------------------------------------------------------------------------
    |
    | 'plain'    — returns (object) ['id' => $sub, 'official_email' => ..., 'email' => ...]. No DB.
    | 'eloquent' — finds user by lookups (token claim => DB column), in order.
    |              Default: official_email → official_email column, then email → email column.
    | FQCN       — your own class implementing SentinelUserResolver contract.
    |
    */
    'resolver' => env('SENTINEL_AUTH_RESOLVER', 'plain'),
    'user_model' => null,
    'lookups' => [
        'official_email' => 'official_email',
        'email' => 'email',
    ],
];
