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
    | 'plain'    — returns (object) ['id' => $sub, 'office_email' => ..., 'email' => ...]. No DB.
    | 'eloquent' — finds user by lookups (token claim => DB column), in order.
    |              Default: office_emails → office_email column, then emails → email column.
    | FQCN       — your own class implementing SentinelUserResolver contract.
    |
    */
    'resolver'   => env('SENTINEL_AUTH_RESOLVER', 'plain'),
    'user_model' => null,
    'lookups'    => [
        'office_emails' => 'office_email',
        'emails'        => 'email',
    ],
];
