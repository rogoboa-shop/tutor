package com.rogoboa.tutor.usermanagement.services;

import com.rogoboa.tutor.integrationservices.email.EmailService;
import com.rogoboa.tutor.integrationservices.exceptions.UserAlreadyExistsException;
import com.rogoboa.tutor.security.JwtAuthenticationException;
import com.rogoboa.tutor.security.JwtService;
import com.rogoboa.tutor.security.otp.OTPCacheService;
import com.rogoboa.tutor.usermanagement.User;
import com.rogoboa.tutor.usermanagement.UserRepository;
import com.rogoboa.tutor.usermanagement.UserRole;
import com.rogoboa.tutor.usermanagement.dtos.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final EmailService emailService;
    private final OTPCacheService otpCacheService;
    private final AuthenticationManager authenticationManager;

    // Manual constructor to use @Lazy
    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            EmailService emailService,
            OTPCacheService otpCacheService,
            @Lazy AuthenticationManager authenticationManager) { // CRITICAL: @Lazy goes here
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.emailService = emailService;
        this.otpCacheService = otpCacheService;
        this.authenticationManager = authenticationManager;
    }

    @Transactional
    public UserResponse register(RegisterRequest request) {

        if (userRepository.existsByEmail(request.email())) {
            throw new UserAlreadyExistsException("An account with this email already exists.");
        }

        // Generate OTP for email verification
        String verificationOTP = otpCacheService.generateOTP(request.email(), "email_verification");

        User user = User.builder()
                .fullName(request.fullName())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .schoolName(request.schoolName())
                .grade(request.grade())
                .role(UserRole.STUDENT)
                .profilePictureUrl("https://api.dicebear.com/7.x/avataaars/svg?seed=" + request.email())
                .emailVerified(false)
                .isActive(true)
                .build();

        User savedUser = userRepository.save(user);

        // Send verification email with OTP
        emailService.sendVerificationEmailWithOTP(
                savedUser.getEmail(),
                verificationOTP,
                savedUser.getFullName()
        );

        log.info("User registered successfully: {}", savedUser.getEmail());

        return new UserResponse(
                savedUser.getId(),
                savedUser.getFullName(),
                savedUser.getEmail(),
                savedUser.getProfilePictureUrl(),
                savedUser.isEmailVerified()
        );
    }

    @Transactional
    public AuthResponse login(AuthRequest request) {
        // Catch the specific "User Not Found" and rethrow as "Bad Credentials"
        // to prevent user enumeration.
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        if (!user.isEmailVerified()) {
            throw new DisabledException("Email not verified. Please verify your email.");
        }

        if (!user.isActive()) {
            throw new DisabledException("Account is disabled");
        }

        // This will throw BadCredentialsException if the password is wrong
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );

        return generateAuthResponse(user);
    }

    @Transactional
    public AuthResponse verifyEmailWithOtp(String email, String otp) {
        // 1. Validate OTP
        otpCacheService.validateOTP(email, otp, "email_verification");

        // 2. Mark as verified
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        user.setEmailVerified(true);
        // Note: We don't need authenticationManager here because
        // the OTP acts as the credential.

        return generateAuthResponse(user);
    }

    public UserResponse getUserByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new UsernameNotFoundException(
                                "User not found with email: " + email
                        )
                );

        return new UserResponse(
                user.getId(),
                user.getFullName(),
                user.getEmail(),
                user.getProfilePictureUrl(),
                user.isEmailVerified()
        );
    }
    /**
     * Shared helper to generate tokens and update login metadata
     */
    private AuthResponse generateAuthResponse(User user) {
        // Update metadata
        user.setLastLogin(LocalDateTime.now());
        User savedUser = userRepository.save(user);

        // Generate JWTs
        String accessToken = jwtService.generateToken(
                savedUser.getId(),
                savedUser.getEmail(),
                savedUser.getRole().name()
        );
        String refreshToken = jwtService.generateRefreshToken(savedUser.getEmail());

        log.info("Session created for user: {}", savedUser.getEmail());

        return new AuthResponse(
                accessToken,
                refreshToken,
                new UserResponse(
                        savedUser.getId(),
                        savedUser.getFullName(),
                        savedUser.getEmail(),
                        savedUser.getProfilePictureUrl(),
                        savedUser.isEmailVerified()
                )
        );
    }

    public void resendVerificationOtp(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));

        if (user.isEmailVerified()) {
            throw new RuntimeException("This email is already verified.");
        }

        // 3. Generate a fresh OTP and send it
        String newOtp = otpCacheService.generateOTP(email, "email_verification");

        emailService.sendVerificationEmailWithOTP(
                user.getEmail(),
                newOtp,
                user.getFullName()
        );

        log.info("Resent verification OTP to: {}", email);
    }

    @Transactional
    public void initiatePasswordReset(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Generate OTP for password reset
        String resetOTP = otpCacheService.generateOTP(email, "password_reset");

        // Send password reset email with OTP
        emailService.sendPasswordResetEmailWithOTP(user.getEmail(), resetOTP, user.getFullName());

        log.info("Password reset OTP sent to: {}", email);
    }

    @Transactional
    public void resetPassword(String email, String otp, String newPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Validate OTP
        boolean isValid = otpCacheService.validateOTP(email, "password_reset", otp);
        if (!isValid) {
            throw new RuntimeException("Invalid or expired OTP");
        }

        // Update password
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Revoke all existing tokens for security
        jwtService.revokeRefreshToken(email);

        log.info("Password reset successfully for: {}", email);
    }

    public void logout(String token) {
        // Extract token without "Bearer " prefix if present
        String cleanToken = token.startsWith("Bearer ") ? token.substring(7) : token;

        // Extract user email from token
        String email = jwtService.extractEmail(cleanToken);

        // Blacklist the access token
        jwtService.blacklistToken(cleanToken);

        // Revoke refresh tokens
        jwtService.revokeRefreshToken(email);

        log.info("User logged out successfully: {}", email);
    }

    @Transactional
    public void deleteAccount(String userId, String email) {
        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!user.getEmail().equals(email)) {
            throw new RuntimeException("Unauthorized to delete this account");
        }

        // Revoke all tokens
        jwtService.revokeRefreshToken(email);

        // Invalidate any pending OTPs
        otpCacheService.invalidateOTP(email, "email_verification");
        otpCacheService.invalidateOTP(email, "password_reset");

        // Delete user
        userRepository.deleteById(UUID.fromString(userId));

        log.info("Account deleted successfully: {}", email);
    }

    public AuthResponse refreshToken(String refreshToken) {
        // Extract email from refresh token
        String email = jwtService.extractEmail(refreshToken);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Validate refresh token
        if (!jwtService.isTokenValid(refreshToken, email)) {
            throw new RuntimeException("Invalid or expired refresh token");
        }

        // Generate new access token
        String newAccessToken = jwtService.generateToken(
                user.getId(),
                user.getEmail(),
                user.getRole().name() // Assuming your UserRole enum has a .name() or toString()
        );

        log.info("Access token refreshed for: {}", email);

        return new AuthResponse(
                newAccessToken,
                refreshToken,
                new UserResponse(
                        user.getId(),
                        user.getFullName(),
                        user.getEmail(),
                        user.getProfilePictureUrl(),
                        user.isEmailVerified()
                )
        );
    }

    /**
     * Validate if a token is blacklisted
     */
    public boolean isTokenBlacklisted(String token) {
        return jwtService.isTokenBlacklisted(token);
    }
}