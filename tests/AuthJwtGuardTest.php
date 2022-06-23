<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/auth.
 *
 * @link     https://github.com/hyperf-ext/auth
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/auth/blob/master/LICENSE
 */
namespace HyperfTest;

use Hyperf\HttpServer\Request;
use Hyperf\Utils\Context;
use Hyperf\Auth\Contracts\AuthenticatableInterface;
use Hyperf\Auth\Contracts\UserProviderInterface;
use Hyperf\Auth\Guards\JwtGuard;
use Hyperf\Jwt\Contracts\JwtSubjectInterface;
use Hyperf\Jwt\Jwt;
use Hyperf\Jwt\JwtFactory;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @internal
 * @coversNothing
 */
class AuthJwtGuardTest extends TestCase
{
    protected function tearDown(): void
    {
        m::close();
    }

    public function testFailValidateCredentials()
    {
        $provider = m::mock(UserProviderInterface::class);
        $container = m::mock(ContainerInterface::class);
        $jwtFactory = m::mock(JwtFactory::class);
        $jwt = m::mock(Jwt::class);
        $dispatcher = m::mock(EventDispatcherInterface::class);

        $user = new AuthTokenGuardTestUser();
        $user->id = 1;
        $user->password = 'hash';
        $request = $this->createRequest(['id' => '1', 'password' => '123456']);
        $provider->shouldReceive('retrieveByCredentials')->once()->with(['id' => '1', 'password' => '123456'])->andReturn($user);
        $provider->shouldReceive('validateCredentials')->once()->andReturn(false);
        $jwt->shouldReceive('fromUser')->andReturn('token');
        $jwt->shouldReceive('setToken');
        $jwtFactory->shouldReceive('make')->once()->andReturn($jwt);
        $dispatcher->shouldReceive('dispatch');

        $guard = new JwtGuard($container, $request, $jwtFactory, $dispatcher, $provider, 'foo');

        $result = $guard->attempt(['id' => '1', 'password' => '123456']);

        $this->assertEquals(false, $result);
    }

    public function testSuccessValidateCredentials()
    {
        $provider = m::mock(UserProviderInterface::class);
        $container = m::mock(ContainerInterface::class);
        $jwtFactory = m::mock(JwtFactory::class);
        $jwt = m::mock(Jwt::class);
        $dispatcher = m::mock(EventDispatcherInterface::class);

        $user = new AuthTokenGuardTestUser();
        $user->id = 1;
        $user->password = 'hash';
        $request = $this->createRequest(['id' => '1', 'password' => '123456']);
        $provider->shouldReceive('retrieveByCredentials')->once()->with(['id' => '1', 'password' => '123456'])->andReturn($user);
        $provider->shouldReceive('validateCredentials')->once()->andReturn(true);
        $jwt->shouldReceive('fromUser')->once()->andReturn('token');
        $jwt->shouldReceive('setToken')->once();
        $jwtFactory->shouldReceive('make')->once()->andReturn($jwt);
        $dispatcher->shouldReceive('dispatch');

        $guard = new JwtGuard($container, $request, $jwtFactory, $dispatcher, $provider, 'foo');

        $result = $guard->attempt(['id' => '1', 'password' => '123456']);

        $this->assertEquals('token', $result);
    }

    protected function createRequest(array $params = [], array $headers = [])
    {
        $request = new \Hyperf\HttpMessage\Server\Request('GET', '/');
        Context::set(ServerRequestInterface::class, $request->withQueryParams($params)->withHeaders($headers));
        return new Request();
    }
}

class AuthJwtGuardTestUser extends User implements AuthenticatableInterface, JwtSubjectInterface
{
    public $id;

    public function getAuthIdentifier()
    {
        return $this->id;
    }

    public function getJwtIdentifier()
    {
        return $this->id;
    }

    public function getJwtCustomClaims(): array
    {
        return [];
    }
}
