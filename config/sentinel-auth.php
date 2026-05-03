<?php

return [
    'url'         => env('SENTINEL_AUTH_URL'),
    'audience'    => env('SENTINEL_AUTH_AUDIENCE', 'sentinel-api'),
    'default_kid' => env('SENTINEL_AUTH_DEFAULT_KID', 'sentinel-auth'),
    'cache_ttl'   => env('SENTINEL_AUTH_CACHE_TTL', 60), // minutes

    /*
    |--------------------------------------------------------------------------
    | User Resolver
    |--------------------------------------------------------------------------
    |
    | 'plain'    — returns (object) ['id' => $sub]. No DB required.
    | 'eloquent' — finds user by user_column matching sub. Fails if not found.
    | FQCN       — your own class implementing SentinelUserResolver contract.
    |
    */
    'resolver'    => env('SENTINEL_AUTH_RESOLVER', 'plain'),
    'user_model'  => null,
    'user_column' => 'auth_id',
];
