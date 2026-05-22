<?php

declare(strict_types=1);

namespace Sentinel\Auth\Concerns;

use Illuminate\Support\Facades\Log;

trait LogsAuthEvents
{
    /**
     * @param  array<string, mixed>  $context
     */
    private function debug(string $event, array $context = []): void
    {
        if (! config('app.debug', false)) {
            return;
        }

        Log::debug('[sentinel-auth] '.$event, $context);
    }

    /**
     * Render a token for logs without leaking the signed material.
     */
    private function redactToken(?string $token): string
    {
        if ($token === null || $token === '') {
            return '<none>';
        }

        return substr($token, 0, 8).'…('.strlen($token).' chars)';
    }

    /**
     * Render a sub/identifier for logs without exposing the full value.
     */
    private function redactId(?string $id): string
    {
        if ($id === null || $id === '') {
            return '<none>';
        }

        return strlen($id) <= 8 ? $id : substr($id, 0, 8).'…';
    }
}
