<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Cache;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Carbon\Carbon;
use App\Models\PasswordReset;

class AuthController extends Controller
{
    // Register User
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'mobile' => 'nullable|digits:10|unique:users',
            'password' => 'required|confirmed|min:8|regex:/[A-Z]/|regex:/[a-z]/|regex:/[0-9]/|regex:/[@$!%*#?&]/',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = User::create([
            'email' => $request->email,
            'mobile' => $request->mobile,
            'password' => Hash::make($request->password),
        ]);

        if (isset($request->mobile)) {
            $this->sendOtp($request->mobile);
        }

        return response()->json(['message' => 'User registered successfully. Please verify your account.'], 201);
    }

    // Send OTP
    private function sendOtp(string $mobile)
    {
        $otp = random_int(100000, 999999);
        Cache::put('otp_' . $mobile, $otp, now()->addMinutes(10));

        if (app()->environment('local')) {
            Log::info('OTP sent to ' . $mobile . ' with code: ' . $otp);
        }
    }

    // Verify OTP
    public function verifyOtp(Request $request)
    {
        $request->validate([
            'mobile' => 'required|digits:10',
            'otp' => 'required|digits:6',
        ]);

        $key = 'verify-otp:' . $request->ip();
        if (RateLimiter::tooManyAttempts($key, 5)) {
            return response()->json(['error' => 'Too many attempts. Please try again later.'], 429);
        }

        RateLimiter::hit($key, 60);

        $storedOtp = Cache::get('otp_' . $request->mobile);

        if (!$storedOtp || $storedOtp != $request->otp) {
            return response()->json(['error' => 'Invalid or expired OTP.'], 400);
        }

        Cache::forget('otp_' . $request->mobile);

        $user = User::where('mobile', $request->mobile)->firstOrFail();
        $token = JWTAuth::fromUser($user);

        return response()->json(['message' => 'Mobile verified successfully.', 'token' => $token]);
    }

    // Login User
    public function login(Request $request)
    {
        $request->validate([
            'mobile' => 'required|digits:10',
            'password' => 'required|min:8',
        ]);

        $credentials = $request->only(['mobile', 'password']);

        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['error' => 'Invalid credentials.'], 401);
        }

        return response()->json(['message' => 'Login successful.', 'token' => $token]);
    }

    // Refresh Token
    public function refresh()
    {
        $token = JWTAuth::refresh(JWTAuth::getToken());
        return response()->json(['token' => $token]);
    }

    // Logout User
    public function logout()
    {
        JWTAuth::invalidate(JWTAuth::getToken());
        return response()->json(['message' => 'Logged out successfully.']);
    }

    // Get Profile
    public function profile(Request $request)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            return response()->json(['user' => $user]);

        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token has expired. Please log in again.'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Invalid token.'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Token is required.'], 400);
        }
    }    

    public function forgotPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'mobile' => 'required|digits:10|exists:users,mobile',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()->first()], 422);
        }

        $user = User::where('mobile', $request->mobile)->first();
        $token = Str::random(60);

        PasswordReset::create([
            'user_id' => $user->id,
            'mobile' => $request->mobile,
            'token' => $token,
            'created_at' => Carbon::now(),
        ]);

        return response()->json(['message' => 'Password reset link has been sent to your mobile.']);
    }

    /**
     * Handle reset password request.
     */
    public function resetPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'mobile' => 'required|digits:10|exists:users,mobile',
            'token' => 'required',
            'password' => 'required|min:8|confirmed',
        ]);
    
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()->first()], 422);
        }
    
        $resetRecord = \DB::table('password_resets')
            ->where('mobile', $request->mobile)
            ->where('token', $request->token)
            ->first();
    
        if (!$resetRecord) {
            return response()->json(['error' => 'Invalid or expired token.'], 400);
        }
    
        if (Carbon::parse($resetRecord->created_at)->addHour()->isPast()) {
            return response()->json(['error' => 'Token has expired. Please request a new one.'], 400);
        }
    
        $user = User::find($resetRecord->user_id); 
        if (!$user) {
            return response()->json(['error' => 'User not found.'], 404);
        }
    
        $user->password = Hash::make($request->password);
        $user->save();
    
        \DB::table('password_resets')->where('user_id', $user->id)->delete();
    
        return response()->json(['message' => 'Password has been successfully reset.']);
    }
    
}
