<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Contracts\Auth\PasswordBroker;
use Illuminate\Database\MySqlConnection;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\PresenceVerifierInterface;
use Mockery;
use Tests\TestCase;

class PasswordAuthenticationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['app.key' => 'base64:'.base64_encode(str_repeat('a', 32))]);
    }

    public function test_email_password_login_excludes_accounts_without_a_password()
    {
        $this->mockLoginQuery([]);

        $this->postJson(route('login'), [
            'email' => 'user@example.com',
            'password' => 'password123',
        ])->assertUnprocessable()->assertJsonValidationErrors('email');

        $this->assertGuest();
    }

    public function test_email_password_login_still_accepts_an_account_with_a_password()
    {
        $this->mockLoginQuery([(object) [
            'id' => 1,
            'name' => 'Local User',
            'email' => 'user@example.com',
            'password' => Hash::make('password123'),
            'google_id' => null,
        ]]);

        $this->post(route('login'), [
            'email' => 'user@example.com',
            'password' => 'password123',
        ])->assertRedirect('/home');

        $this->assertAuthenticated();
        $this->assertSame(1, auth()->id());
    }

    public function test_public_registration_requires_password_and_rejects_google_identity_fields()
    {
        $presence = Mockery::mock(PresenceVerifierInterface::class);
        $presence->shouldReceive('getCount')->andReturn(0);
        Validator::getFacadeRoot()->setPresenceVerifier($presence);

        $this->postJson(route('register'), [
            'name' => 'Spoofed Google User',
            'email' => 'user@example.com',
            'google_id' => 'untrusted-google-id',
            'avatar' => 'https://example.com/avatar.jpg',
            'email_verified_at' => '2026-01-01 00:00:00',
        ])->assertUnprocessable()->assertJsonValidationErrors([
            'password', 'google_id', 'avatar', 'email_verified_at',
        ]);

        $this->assertGuest();
    }

    public function test_password_reset_can_set_a_password_without_changing_google_identity()
    {
        Event::fake([PasswordReset::class]);
        $user = Mockery::mock(User::class)->makePartial();
        $user->forceFill([
            'id' => 1,
            'email' => 'user@example.com',
            'google_id' => 'google-123',
            'avatar' => 'https://example.com/avatar.jpg',
            'email_verified_at' => now(),
            'password' => null,
        ]);
        $user->exists = true;
        $user->shouldReceive('save')->once()->andReturn(true);
        $broker = Mockery::mock(PasswordBroker::class);
        Password::shouldReceive('broker')->once()->andReturn($broker);
        $broker->shouldReceive('reset')->once()->andReturnUsing(function ($credentials, $reset) use ($user) {
            $this->assertSame('valid-reset-token', $credentials['token']);
            $this->assertSame('user@example.com', $credentials['email']);
            $reset($user, $credentials['password']);

            return Password::PASSWORD_RESET;
        });

        $this->post(route('password.update'), [
            'email' => 'user@example.com',
            'token' => 'valid-reset-token',
            'password' => 'new-password123',
            'password_confirmation' => 'new-password123',
        ])->assertRedirect('/home');

        $this->assertTrue(Hash::check('new-password123', $user->password));
        $this->assertSame('google-123', $user->google_id);
        $this->assertSame('https://example.com/avatar.jpg', $user->avatar);
        $this->assertNotEmpty($user->remember_token);
        $this->assertAuthenticatedAs($user);
        Event::assertDispatched(PasswordReset::class);
    }

    private function mockLoginQuery(array $rows)
    {
        $connection = Mockery::mock(MySqlConnection::class)->makePartial();
        $connection->__construct(function () {
            throw new \RuntimeException('This test must not connect to a real database.');
        }, 'auth_test');

        $connection->shouldReceive('select')->once()->withArgs(function ($sql, $bindings) {
            $this->assertStringContainsString('`password` is not null', $sql);
            $this->assertSame(['user@example.com'], $bindings);

            return true;
        })->andReturn($rows);

        config(['database.connections.auth_test' => ['driver' => 'mysql']]);
        $this->app['db']->extend('auth_test', function () use ($connection) {
            return $connection;
        });
        $this->app['db']->setDefaultConnection('auth_test');
    }
}
