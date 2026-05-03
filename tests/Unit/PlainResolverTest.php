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

    public function test_exposes_office_email_and_email_from_token_claims(): void
    {
        $token = (object) [
            'office_emails' => 'work@acme.com',
            'emails' => 'personal@home.com',
        ];

        $result = $this->resolver->resolve('sub-1', $token);

        $this->assertSame('work@acme.com', $result->office_email);
        $this->assertSame('personal@home.com', $result->email);
    }

    public function test_email_fields_are_null_when_claims_missing(): void
    {
        $result = $this->resolver->resolve('sub-1', (object) []);

        $this->assertNull($result->office_email);
        $this->assertNull($result->email);
    }

    public function test_empty_string_claims_become_null(): void
    {
        $token = (object) ['office_emails' => '', 'emails' => ''];

        $result = $this->resolver->resolve('sub-1', $token);

        $this->assertNull($result->office_email);
        $this->assertNull($result->email);
    }

    public function test_non_string_claims_become_null(): void
    {
        $token = (object) ['office_emails' => ['a@b.com'], 'emails' => 123];

        $result = $this->resolver->resolve('sub-1', $token);

        $this->assertNull($result->office_email);
        $this->assertNull($result->email);
    }

    public function test_each_call_returns_a_new_object(): void
    {
        $first = $this->resolver->resolve('same-sub', (object) []);
        $second = $this->resolver->resolve('same-sub', (object) []);

        $this->assertNotSame($first, $second);
        $this->assertSame($first->id, $second->id);
    }
}
