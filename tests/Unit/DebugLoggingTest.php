<?php

declare(strict_types=1);

namespace Sentinel\Auth\Tests\Unit;

use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Sentinel\Auth\Tests\TestCase;

class DebugLoggingTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
        Http::preventStrayRequests();
    }

    public function test_emits_debug_logs_when_app_debug_is_true(): void
    {
        config(['app.debug' => true]);

        $captured = [];
        Log::listen(function (MessageLogged $event) use (&$captured) {
            if (str_starts_with($event->message, '[sentinel-auth]')) {
                $captured[] = $event->message;
            }
        });

        $token = $this->buildToken();
        $this->fakeJwks(static::$primaryKey);

        $this->makeGuard($token)->user();

        $this->assertContains('[sentinel-auth] guard.start', $captured);
        $this->assertContains('[sentinel-auth] decode.start', $captured);
        $this->assertContains('[sentinel-auth] decode.success', $captured);
        $this->assertContains('[sentinel-auth] guard.resolver.success', $captured);
    }

    public function test_emits_no_debug_logs_when_app_debug_is_false(): void
    {
        config(['app.debug' => false]);

        $captured = [];
        Log::listen(function (MessageLogged $event) use (&$captured) {
            if (str_starts_with($event->message, '[sentinel-auth]')) {
                $captured[] = $event->message;
            }
        });

        $token = $this->buildToken();
        $this->fakeJwks(static::$primaryKey);

        $this->makeGuard($token)->user();

        $this->assertEmpty($captured);
    }

    public function test_token_is_redacted_in_logs(): void
    {
        config(['app.debug' => true]);

        $captured = [];
        Log::listen(function (MessageLogged $event) use (&$captured) {
            $captured[] = ['message' => $event->message, 'context' => $event->context];
        });

        $token = $this->buildToken();
        $this->fakeJwks(static::$primaryKey);

        $this->makeGuard($token)->user();

        $serialized = json_encode($captured);
        $this->assertStringNotContainsString($token, $serialized);
    }

    public function test_logs_failure_with_exception_class(): void
    {
        config(['app.debug' => true]);

        $captured = [];
        Log::listen(function (MessageLogged $event) use (&$captured) {
            if (str_contains($event->message, 'guard.failure')) {
                $captured[] = $event->context;
            }
        });

        $this->fakeJwks(static::$primaryKey);

        try {
            $this->makeGuard('not-a-jwt')->user();
        } catch (\Throwable) {
            // expected
        }

        $this->assertNotEmpty($captured);
        $this->assertArrayHasKey('exception', $captured[0]);
    }
}
