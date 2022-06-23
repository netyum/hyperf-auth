<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace Hyperf\Auth\Events;

use Hyperf\Auth\Contracts\AuthManagerInterface;

class AuthManagerResolved
{
    /**
     * @var \Hyperf\Auth\Contracts\AuthManagerInterface
     */
    public $auth;

    /**
     * Create a new event instance.
     */
    public function __construct(AuthManagerInterface $auth)
    {
        $this->auth = $auth;
    }
}
