package com.rogoboa.tutor.usermanagement.services;

import com.rogoboa.tutor.integrationservices.email.EmailService;
import com.rogoboa.tutor.usermanagement.dtos.*;
import com.rogoboa.tutor.usermanagement.services.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final EmailService emailService;

    // --- ADD THIS LINE ---
    @Value("${app.env:dev}")
    private String env;
    // ---------------------

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<UserResponse>> register(@Valid @RequestBody RegisterRequest request) {
        // No try-catch needed! Let the Global Handler handle the errors.
        UserResponse user = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new ApiResponse<>(true, "Registration successful. Please check your email.", user));
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<ApiResponse<Void>> resendVerificationEmail(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        authService.resendVerificationOtp(email);
        return ResponseEntity.ok(new ApiResponse<>(true, "New verification code sent", null));
    }

    @PostMapping("/verify-email")
    public ResponseEntity<ApiResponse<UserResponse>> verifyEmail(
            @Valid @RequestBody VerifyOtpRequest request,
            HttpServletResponse response
    ) {
        AuthResponse auth = authService.verifyEmailWithOtp(request.email(), request.otp());
        addAuthCookies(response, auth);

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                "Email verified and logged in successfully",
                auth.user()
        ));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<UserResponse>> login(
            @Valid @RequestBody AuthRequest request,
            HttpServletResponse response
    ) {
        AuthResponse auth = authService.login(request);
        addAuthCookies(response, auth);

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                "Login successful",
                auth.user()
        ));
    }

    private void addAuthCookies(HttpServletResponse response, AuthResponse auth) {
        boolean isProd = "prod".equalsIgnoreCase(env);

        Cookie acc = new Cookie("access_token", auth.accessToken());
        acc.setHttpOnly(true);
        acc.setSecure(isProd);
        acc.setPath("/");
        acc.setMaxAge(24 * 60 * 60);
        response.addCookie(acc);

        Cookie ref = new Cookie("refresh_token", auth.refreshToken());
        ref.setHttpOnly(true);
        ref.setSecure(isProd);
        ref.setPath("/");
        ref.setMaxAge(7 * 24 * 60 * 60);
        response.addCookie(ref);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        String token = extractTokenFromCookie(request, "access_token");

        if (token != null) {
            authService.logout(token);
        }

        // Clear cookies
        Cookie accessTokenCookie = new Cookie("access_token", "");
        accessTokenCookie.setMaxAge(0);
        accessTokenCookie.setPath("/");

        Cookie refreshTokenCookie = new Cookie("refresh_token", "");
        refreshTokenCookie.setMaxAge(0);
        refreshTokenCookie.setPath("/");

        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);

        return ResponseEntity.ok(new ApiResponse<>(true, "Logout successful", null));
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(false, "Not authenticated", null));
        }

        // Usually, you'd fetch the latest user data from the DB using the email/username
        String email = authentication.getName();
        UserResponse user = authService.getUserByEmail(email);

        return ResponseEntity.ok(new ApiResponse<>(true, "User session is active", user));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        String refreshToken = extractTokenFromCookie(request, "refresh_token");

        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(false, "No refresh token found", null));
        }

        AuthResponse authResponse = authService.refreshToken(refreshToken);

        // Update access token cookie
        Cookie accessTokenCookie = new Cookie("access_token", authResponse.accessToken());
        accessTokenCookie.setHttpOnly(true);
        boolean isProd = "prod".equalsIgnoreCase(env);
        accessTokenCookie.setSecure(isProd);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(24 * 60 * 60);

        response.addCookie(accessTokenCookie);

        return ResponseEntity.ok(new ApiResponse<>(true, "Token refreshed", authResponse));
    }

    @DeleteMapping("/delete-account")
    public ResponseEntity<ApiResponse<Void>> deleteAccount(
            Authentication authentication,
            HttpServletResponse response
    ) {
        String email = authentication.getName();
        // Extract user ID from authentication or fetch from database
        // For now, assuming we can get it from the service
        authService.deleteAccount(null, email); // You'll need to adjust this

        // Clear cookies
        Cookie accessTokenCookie = new Cookie("access_token", "");
        accessTokenCookie.setMaxAge(0);
        accessTokenCookie.setPath("/");

        Cookie refreshTokenCookie = new Cookie("refresh_token", "");
        refreshTokenCookie.setMaxAge(0);
        refreshTokenCookie.setPath("/");

        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);

        return ResponseEntity.ok(new ApiResponse<>(true, "Account deleted successfully", null));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        authService.initiatePasswordReset(email);
        return ResponseEntity.ok(new ApiResponse<>(
                true,
                "Password reset code sent to your email",
                null
        ));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request.email(), request.otp(), request.newPassword());
        return ResponseEntity.ok(new ApiResponse<>(
                true,
                "Password reset successful. You can now login with your new password.",
                null
        ));
    }

    private String extractTokenFromCookie(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            return Arrays.stream(request.getCookies())
                    .filter(cookie -> cookieName.equals(cookie.getName()))
                    .map(Cookie::getValue)
                    .findFirst()
                    .orElse(null);
        }
        return null;
    }
}