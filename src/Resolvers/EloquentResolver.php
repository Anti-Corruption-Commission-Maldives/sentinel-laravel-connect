<?php

declare(strict_types=1);

namespace Sentinel\Auth\Resolvers;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Eloquent\Model;
use Sentinel\Auth\Contracts\SentinelUserResolver;

class EloquentResolver implements SentinelUserResolver
{
    /**
     * @param  array<string, string>  $lookups  Map of token claim => DB column. Tried in order.
     */
    public function __construct(
        private string $model,
        private array $lookups = [
            'office_emails' => 'office_email',
            'emails' => 'email',
        ],
    ) {}

    public function resolve(string $sub, object $token): Model
    {
        foreach ($this->lookups as $claim => $column) {
            $value = $token->{$claim} ?? null;
            if (! is_string($value) || $value === '') {
                continue;
            }

            $user = ($this->model)::where($column, $value)->first();
            if ($user) {
                return $user;
            }
        }

        throw new AuthenticationException('User not found.');
    }
}
