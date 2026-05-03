<?php

declare(strict_types=1);

namespace Sentinel\Auth\Tests\Unit;

use Sentinel\Auth\Resolvers\PlainResolver;
use Sentinel\Auth\Tests\TestCase;

class PlainResolverTest extends TestCase
{
    private PlainResolver $resolver;

    protected function setUp(): void
    {
        parent::setUp();
        $this->resolver = new PlainResolver;
    }

    public function test_returns_object_with_id_equal_to_sub(): void
    {
        $result = $this->resolver->resolve('user-abc', (object) []);

        $this->assertIsObject($result);
        $this->assertSame('user-abc', $result->id);
    }

    public function test_id_is_exact_sub_value_no_transformation(): void
    {
        $result = $this->resolver->resolve('  spaces-and-CAPS-123  ', (object) []);

        $this->assertSame('  spaces-and-CAPS-123  ', $result->id);
    }

    public function test_does_not_use_token_claims_for_resolution(): void
    {
        $token = (object) ['email' => 'user@example.com', 'name' => 'John'];

        $result = $this->resolver->resolve('sub-value', $token);

        $this->assertSame('sub-value', $result->id);
        $this->assertFalse(isset($result->email));
        $this->assertFalse(isset($result->name));
    }

    public function test_each_call_returns_a_new_object(): void
    {
        $first = $this->resolver->resolve('same-sub', (object) []);
        $second = $this->resolver->resolve('same-sub', (object) []);

        $this->assertNotSame($first, $second);
        $this->assertSame($first->id, $second->id);
    }
}
