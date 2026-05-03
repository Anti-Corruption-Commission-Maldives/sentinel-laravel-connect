<?php

declare(strict_types=1);

namespace Sentinel\Auth\Resolvers;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Eloquent\Model;
use Sentinel\Auth\Contracts\SentinelUserResolver;

class EloquentResolver implements SentinelUserResolver
{
    private string $model;

    private string $column;

    public function __construct(string $model, string $column = 'auth_id')
    {
        $this->model = $model;
        $this->column = $column;
    }

    public function resolve(string $sub, object $token): Model
    {
        $user = ($this->model)::where($this->column, $sub)->first();

        if (! $user) {
            throw new AuthenticationException('User not found.');
        }

        return $user;
    }
}
