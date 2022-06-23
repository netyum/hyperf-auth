<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace Hyperf\Auth\Contracts\Access;

interface Authorizable
{
    /**
     * Determine if the entity has a given ability.
     *
     * @param array|mixed $arguments
     */
    public function can(string $ability, $arguments = []): bool;
}
