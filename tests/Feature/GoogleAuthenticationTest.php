<?php

namespace Tests\Feature;

use App\Models\User;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Auth\Events\Registered;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\Event;
use Laravel\Socialite\Facades\Socialite;
use Mockery;
use Tests\TestCase;

class GoogleAuthenticationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'app.key' => 'base64:'.base64_encode(str_repeat('a', 32)),
            'services.google.client_id' => 'google-client',
            'services.google.client_secret' => 'google-secret',
            'services.google.redirect' => 'http://localhost/auth/google/callback',
        ]);
    }

    public function test_google_redirect_stores_oauth_state_in_the_session()
    {
        $response = $this->get(route('auth.google'));

        $response->assertRedirect();
        parse_str(parse_url($response->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->assertSame('google-client', $query['client_id']);
        $this->assertSame(config('services.google.redirect'), $query['redirect_uri']);
        $this->assertNotEmpty($query['state']);
        $response->assertSessionHas('state', $query['state']);
    }

    public function test_google_login_reports_missing_configuration()
    {
        config(['services.google.client_secret' => null]);

        $this->get(route('auth.google'))
            ->assertRedirect(route('login'))
            ->assertSessionHasErrors('email');
        $this->assertGuest();
    }

    public function test_callback_rejects_invalid_oauth_state_before_contacting_google()
    {
        // An empty queue also ensures no external HTTP request is made.
        $this->mockGoogleResponses([]);

        $this->withSession(['state' => 'expected'])->get($this->callbackUrl('wrong'))
            ->assertRedirect(route('login'))
            ->assertSessionHasErrors('email')
            ->assertSessionMissing('state');
        $this->assertGuest();
    }

    public function test_callback_handles_cancelled_authorization()
    {
        $this->withSession(['state' => 'expected'])
            ->get(route('auth.google.callback', ['error' => 'access_denied']))
            ->assertRedirect(route('login'))
            ->assertSessionHasErrors('email')
            ->assertSessionMissing('state');
        $this->assertGuest();
    }

    public function test_callback_handles_google_http_failure()
    {
        $this->mockGoogleResponses([new Response(400, [], '{"error":"invalid_grant"}')]);

        $this->withSession(['state' => 'expected'])->get($this->callbackUrl())
            ->assertRedirect(route('login'))
            ->assertSessionHasErrors('email');
        $this->assertGuest();
    }

    public function test_unverified_google_email_cannot_register_or_log_in()
    {
        $this->mockGoogleProfile(['email_verified' => false]);
        $users = Mockery::mock(User::class)->makePartial();
        $users->shouldNotReceive('newQuery');
        $this->app->instance(User::class, $users);

        $this->withSession(['state' => 'expected'])->get($this->callbackUrl())
            ->assertRedirect(route('login'))
            ->assertSessionHasErrors('email');
        $this->assertGuest();
    }

    public function test_new_google_user_has_no_password_and_has_a_verified_email()
    {
        Event::fake([Registered::class]);
        $this->mockGoogleProfile();
        $user = Mockery::mock(User::class)->makePartial();
        $user->google_id = 'google-123';
        $user->shouldReceive('save')->once()->andReturnUsing(function () use ($user) {
            $this->assertNull($user->password);
            $this->assertNotNull($user->email_verified_at);
            $this->assertSame('Google User', $user->name);
            $this->assertSame('google@example.com', $user->email);
            $this->assertSame('https://example.com/avatar.jpg', $user->avatar);
            $user->id = 1;
            $user->exists = true;

            return true;
        });
        $this->mockUserLookup($user, false);

        $this->withSession(['state' => 'expected', 'url.intended' => '/home'])
            ->get($this->callbackUrl())->assertRedirect('/home');

        $this->assertAuthenticatedAs($user);
        Event::assertDispatched(Registered::class, function ($event) use ($user) {
            return $event->user === $user;
        });
    }

    public function test_existing_google_user_keeps_local_password_and_email()
    {
        Event::fake([Registered::class]);
        $this->mockGoogleProfile();
        $user = Mockery::mock(User::class)->makePartial();
        $user->forceFill([
            'id' => 7,
            'google_id' => 'google-123',
            'email' => 'original@example.com',
            'password' => 'existing-password-hash',
            'email_verified_at' => now(),
        ]);
        $user->exists = true;
        $user->shouldReceive('save')->once()->andReturn(true);
        $this->mockUserLookup($user);

        $this->withSession(['state' => 'expected'])->get($this->callbackUrl())
            ->assertRedirect('/home');

        $this->assertAuthenticatedAs($user);
        $this->assertSame('original@example.com', $user->email);
        $this->assertSame('existing-password-hash', $user->password);
        $this->assertSame('https://example.com/avatar.jpg', $user->avatar);
        Event::assertNotDispatched(Registered::class);
    }

    public function test_google_email_match_does_not_link_a_local_account()
    {
        $this->mockGoogleProfile();
        $user = Mockery::mock(User::class)->makePartial();
        $user->google_id = 'google-123';
        $user->shouldNotReceive('save');
        $this->mockUserLookup($user, true);

        $this->withSession(['state' => 'expected'])->get($this->callbackUrl())
            ->assertRedirect(route('login'))
            ->assertSessionHasErrors('email');
        $this->assertGuest();
    }

    public function test_google_only_user_is_directed_to_create_password_before_confirmation()
    {
        $user = new User(['google_id' => 'google-123', 'password' => null]);
        $user->id = 1;

        $this->actingAs($user)->get(route('password.confirm'))
            ->assertRedirect(route('password.request'))
            ->assertSessionHas('status');
    }

    private function callbackUrl($state = 'expected')
    {
        return route('auth.google.callback', ['code' => 'authorization-code', 'state' => $state]);
    }

    private function mockGoogleProfile(array $attributes = [])
    {
        $profile = array_merge([
            'sub' => 'google-123',
            'name' => 'Google User',
            'email' => 'google@example.com',
            'email_verified' => true,
            'picture' => 'https://example.com/avatar.jpg',
        ], $attributes);

        $this->mockGoogleResponses([
            new Response(200, [], json_encode(['access_token' => 'google-access-token', 'token_type' => 'Bearer'])),
            new Response(200, [], json_encode($profile)),
        ]);
    }

    private function mockGoogleResponses(array $responses)
    {
        $provider = Socialite::driver('google');
        $provider->setHttpClient(new Client([
            'handler' => HandlerStack::create(new MockHandler($responses)),
        ]));

        // The driver is created before the test HTTP request starts.
        $this->app->rebinding('request', function ($app, $request) use ($provider) {
            $provider->setRequest($request);
        });
    }

    private function mockUserLookup(User $user, $emailExists = null)
    {
        $users = Mockery::mock(User::class)->makePartial();
        $query = Mockery::mock(Builder::class);
        $users->shouldReceive('newQuery')->once()->andReturn($query);
        $query->shouldReceive('firstOrNew')->once()
            ->with(['google_id' => 'google-123'])->andReturn($user);

        if ($emailExists !== null) {
            $emailQuery = Mockery::mock(Builder::class);
            $users->shouldReceive('newQuery')->once()->andReturn($emailQuery);
            $emailQuery->shouldReceive('where')->once()->with('email', 'google@example.com')->andReturnSelf();
            $emailQuery->shouldReceive('exists')->once()->andReturn($emailExists);
        }

        $this->app->instance(User::class, $users);
    }
}
