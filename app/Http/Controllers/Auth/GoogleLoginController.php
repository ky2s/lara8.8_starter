<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Providers\RouteServiceProvider;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\InvalidStateException;

class GoogleLoginController extends Controller
{
    public function __construct()
    {
        $this->middleware('guest');
    }

    public function redirect()
    {
        if (! $this->isConfigured()) {
            return $this->failed('Login Google belum dikonfigurasi.');
        }

        return Socialite::driver('google')->redirect();
    }

    public function callback(Request $request, User $users)
    {
        if (! $this->isConfigured()) {
            return $this->failed('Login Google belum dikonfigurasi.');
        }

        if ($request->has('error')) {
            $request->session()->forget('state');

            return $this->failed('Login Google dibatalkan. Silakan coba lagi.');
        }

        try {
            // Keep Socialite's session state validation enabled.
            $googleUser = Socialite::driver('google')->user();
        } catch (InvalidStateException | GuzzleException $exception) {
            return $this->failed('Login Google gagal. Silakan coba lagi.');
        }

        $profile = [
            'google_id' => $googleUser->getId(),
            'email' => $googleUser->getEmail(),
            'name' => $googleUser->getName() ?: $googleUser->getEmail(),
            'avatar' => $googleUser->getAvatar(),
            'email_verified' => $googleUser->getRaw()['email_verified'] ?? false,
        ];

        if (Validator::make($profile, [
            'google_id' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:255'],
            'name' => ['required', 'string', 'max:255'],
            'avatar' => ['nullable', 'url'],
            'email_verified' => ['accepted'],
        ])->fails()) {
            return $this->failed('Google harus memberikan profil dan email yang sudah terverifikasi.');
        }

        $user = $users->newQuery()->firstOrNew(['google_id' => $profile['google_id']]);
        $registered = ! $user->exists;

        if ($registered) {
            // An email match alone must not link an existing local account.
            if ($users->newQuery()->where('email', $profile['email'])->exists()) {
                return $this->failed('Email sudah terdaftar. Silakan masuk menggunakan password atau reset password.');
            }

            $user->fill([
                'name' => $profile['name'],
                'email' => $profile['email'],
                'password' => null,
            ]);
            $user->email_verified_at = now();
        }

        $user->avatar = $profile['avatar'];
        $user->save();

        if ($registered) {
            event(new Registered($user));
        }

        Auth::guard('web')->login($user);
        $request->session()->regenerate();

        return redirect()->intended(RouteServiceProvider::HOME);
    }

    private function isConfigured()
    {
        return config('services.google.client_id')
            && config('services.google.client_secret')
            && config('services.google.redirect');
    }

    private function failed($message)
    {
        return redirect()->route('login')->withErrors(['email' => $message]);
    }
}
