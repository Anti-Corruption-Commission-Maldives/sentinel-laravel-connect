# sentinel/laravel-connect

Laravel auth guard for validating JWTs issued by [Sentinel Auth](https://github.com/Anti-Corruption-Commission-Maldives/sentinel-api). Install this package on any Laravel app that needs to authenticate requests from Sentinel.

## How it works

```
Request → Bearer token → Validate JWT (JWKS) → Resolve local user → Auth guard
```

1. Extracts the Bearer token from the request
2. Fetches the public key from Sentinel's JWKS endpoint (cached)
3. Validates signature, expiry, and audience
4. Passes the verified token to your resolver to find/return a local user
5. User is available via `auth()->user()` / `$request->user()`

## Requirements

- PHP ^8.0
- Laravel ^8.0 | ^9.0 | ^10.0 | ^11.0 | ^12.0

## Installation

```bash
composer require sentinel/laravel-connect
php artisan vendor:publish --tag=sentinel-auth-config
```

Add to `.env`:

```env
SENTINEL_AUTH_URL=https://auth.example.com
SENTINEL_AUTH_AUDIENCE=your-app-name
```

Register the guard in `config/auth.php`:

```php
'guards' => [
    'api' => [
        'driver'   => 'passport-token',
        'provider' => 'users',
    ],
],
```

## User Resolvers

The package ships with two built-in resolvers. Choose based on your app's needs.

### Plain (default)

Returns a plain object with the token `sub` claim as `id`. No database required.

```php
// config/sentinel-auth.php
'resolver' => 'plain',
```

```php
auth()->user()->id; // the sub claim value
```

Use this for simple apps or services that only need the user's identity, not a local DB record.

---

### Eloquent

Looks up a local Eloquent model by matching a column against the `sub` claim. Throws `AuthenticationException` if the user is not found — **does not create users**.

```php
// config/sentinel-auth.php
'resolver'    => 'eloquent',
'user_model'  => \App\Models\User::class,
'user_column' => 'auth_id', // column matched against sub claim
```

The user **must already exist** in your database. Use this for apps where users are pre-provisioned.

---

### Custom Resolver

For apps with specific requirements — JIT provisioning, multi-step lookup, attaching token claims to the user, etc.

Implement `Sentinel\Auth\Contracts\SentinelUserResolver`:

```php
<?php

namespace App\Auth;

use Illuminate\Auth\AuthenticationException;
use Lcobucci\JWT\UnencryptedToken;
use Sentinel\Auth\Contracts\SentinelUserResolver;
use App\Models\User;

class SentinelResolver implements SentinelUserResolver
{
    public function resolve(string $sub, object $token): User
    {
        // Try existing user first
        $user = User::where('auth_id', $sub)
            ->orWhere('email', $token->email ?? null)
            ->first();

        if ($user) {
            if (! $user->auth_id) {
                $user->update(['auth_id' => $sub]);
            }
        } else {
            // JIT provision — create on first login
            $user = User::create([
                'auth_id' => $sub,
                'name'    => $token->name ?? '',
                'email'   => $token->email ?? null,
            ]);
        }

        // Attach transient token claims (not persisted)
        $user->token_context = $token->context ?? null;

        return $user;
    }
}
```

> **Contract:** `resolve()` must either return a user or throw `AuthenticationException`. Never return `null`.

Register in `AppServiceProvider`:

```php
use Sentinel\Auth\Contracts\SentinelUserResolver;
use App\Auth\SentinelResolver;

public function register(): void
{
    $this->app->bind(SentinelUserResolver::class, SentinelResolver::class);
}
```

Set in config:

```php
// config/sentinel-auth.php
'resolver' => \App\Auth\SentinelResolver::class,
```

## Protecting Routes

Apply `auth:api` middleware to routes that require authentication:

```php
// routes/api.php

// Protected
Route::middleware('auth:api')->group(function () {
    Route::get('/profile', [ProfileController::class, 'show']);
    Route::get('/documents', [DocumentController::class, 'index']);
});

// Public — no auth required
Route::get('/health', fn () => response()->json(['status' => 'ok']));
```

Or per route:

```php
Route::get('/reports', [ReportController::class, 'index'])->middleware('auth:api');
```

## Accessing the User

Once authenticated, the resolved user is available anywhere in the request lifecycle:

```php
// Controller
public function show(Request $request)
{
    $user = $request->user();   // resolved user
    $user = auth()->user();     // same
    $user = Auth::user();       // same
}

// Middleware
public function handle(Request $request, Closure $next): mixed
{
    $userId = $request->user()->id;
    // ...
    return $next($request);
}
```

The guard resolves and caches the user on the first call. Subsequent calls within the same request return the cached user — JWKS is not re-fetched.

## Configuration Reference

```php
// config/sentinel-auth.php
return [
    // Sentinel Auth server base URL
    'url'          => env('SENTINEL_AUTH_URL'),

    // Expected audience claim in tokens — must match what Sentinel issues
    'audience'     => env('SENTINEL_AUTH_AUDIENCE', 'sentinel-api'),

    // Default key ID used when token has no kid header
    'default_kid'  => env('SENTINEL_AUTH_DEFAULT_KID', 'sentinel-auth'),

    // How long to cache the JWKS public key (minutes)
    'cache_ttl'    => env('SENTINEL_AUTH_CACHE_TTL', 60),

    // Resolver: 'plain' | 'eloquent' | FQCN of custom class
    'resolver'     => env('SENTINEL_AUTH_RESOLVER', 'plain'),

    // Required when resolver = 'eloquent'
    'user_model'   => null,

    // Column matched against the sub claim (eloquent resolver only)
    'user_column'  => 'auth_id',
];
```

## Key Rotation

The guard handles key rotation automatically:

1. First request fetches JWKS and caches the public key
2. If signature validation fails (stale key), the cache is busted and JWKS re-fetched
3. Validation is retried once with the fresh key
4. If validation still fails, `AuthenticationException` is thrown

## Running Tests

```bash
composer test
```
