<?php

namespace App\Http\Middleware;

use Illuminate\Auth\Middleware\Authenticate as Middleware;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\JWTException;
use Closure;

class Authenticate extends Middleware
{
    /**
     * Get the path the user should be redirected to when they are not authenticated.
     */
    protected function redirectTo(Request $request): ?string
    {
        return $request->expectsJson() ? null : route('login');
    }

    /**
     * Handle an incoming request.
     */
    public function handle($request, Closure $next, ...$guards)
    {
        try {
            // Check if the token is valid
            $user = JWTAuth::parseToken()->authenticate();
        } catch (TokenExpiredException $e) {
            // Token has expired
            return response()->json(['error' => 'Token has expired. Please log in again.'], 401);
        } catch (TokenInvalidException $e) {
            // Token is invalid
            return response()->json(['error' => 'You are not authenticated. Please provide a valid token.'], 401);
        } catch (JWTException $e) {
            // Token is missing
            return response()->json(['error' => 'Token is required to access this resource.'], 401);
        }

        return $next($request);
    }
}
