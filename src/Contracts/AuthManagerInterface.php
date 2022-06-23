<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace Hyperf\Auth\Contracts;

interface AuthManagerInterface
{
    /**
     * Get a guard instance by name.
     *
     * @return \Hyperf\Auth\Contracts\GuardInterface|\Hyperf\Auth\Contracts\StatefulGuardInterface|\Hyperf\Auth\Contracts\StatelessGuardInterface
     */
    public function guard(?string $name = null): GuardInterface;

    /**
     * Set the default guard the factory should serve.
     */
    public function shouldUse(string $name): void;
}
