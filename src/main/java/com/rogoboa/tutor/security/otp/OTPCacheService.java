package com.rogoboa.tutor.security.otp;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Service
public class OTPCacheService {

    private final Cache<String, String> otpCache;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${otp.ttl.login:5}")
    private long loginTtlMinutes;
    @Value("${otp.ttl.password_reset:15}")
    private long passwordResetTtlMinutes;
    @Value("${otp.ttl.email_verification:10}")
    private long emailVerificationTtlMinutes;

    public OTPCacheService() {
        // Initialize Caffeine cache with max TTL of 15 minutes
        this.otpCache = Caffeine.newBuilder()
                .expireAfterWrite(15, TimeUnit.MINUTES)
                .maximumSize(10_000)
                .build();
    }

    /**
     * Generate and store OTP with expiration.
     */
    public String generateOTP(String key, String purpose) {
        String otp = OTPGenerator.generateNumericOTP();
        String cacheKey = buildCacheKey(purpose, key);

        // Store OTP with metadata including expiration time
        long expirationTime = System.currentTimeMillis() + getTtlForPurpose(purpose).toMillis();
        String value = otp + ":" + expirationTime;

        otpCache.put(cacheKey, value);
        return otp;
    }

    /**
     * Validate and consume OTP (single-use) in a constant-time manner.
     */
    public boolean validateOTP(String key, String purpose, String otp) {
        String cacheKey = buildCacheKey(purpose, key);
        String cachedValue = otpCache.getIfPresent(cacheKey);

        if (cachedValue == null) return false;

        // Parse OTP and expiration time
        String[] parts = cachedValue.split(":", 2);
        if (parts.length != 2) return false;

        String cachedOtp = parts[0];
        long expirationTime = Long.parseLong(parts[1]);

        // Check if expired
        if (System.currentTimeMillis() > expirationTime) {
            otpCache.invalidate(cacheKey);
            return false;
        }

        // Constant-time comparison
        boolean isMatch = MessageDigest.isEqual(
                cachedOtp.getBytes(StandardCharsets.UTF_8),
                otp.getBytes(StandardCharsets.UTF_8)
        );

        // Consume OTP on successful validation
        if (isMatch) {
            otpCache.invalidate(cacheKey);
        }

        return isMatch;
    }

    /**
     * Invalidate OTP
     */
    public void invalidateOTP(String key, String purpose) {
        otpCache.invalidate(buildCacheKey(purpose, key));
    }

    /**
     * Request a new OTP (invalidates old one first)
     */
    public String requestNewOTP(String key, String purpose) {
        invalidateOTP(key, purpose);
        return generateOTP(key, purpose);
    }

    /**
     * Get cached OTP without consuming it (for verification preview)
     */
    public String getCachedOTP(String cacheKey) {
        String cachedValue = otpCache.getIfPresent(cacheKey);
        if (cachedValue == null) return null;

        String[] parts = cachedValue.split(":", 2);
        if (parts.length != 2) return null;

        // Check if expired
        long expirationTime = Long.parseLong(parts[1]);
        if (System.currentTimeMillis() > expirationTime) {
            otpCache.invalidate(cacheKey);
            return null;
        }

        return parts[0];
    }

    private String buildCacheKey(String purpose, String key) {
        return "otp:" + purpose + ":" + key;
    }

    private Duration getTtlForPurpose(String purpose) {
        return switch (purpose) {
            case "password_reset" -> Duration.ofMinutes(passwordResetTtlMinutes);
            case "email_verification" -> Duration.ofMinutes(emailVerificationTtlMinutes);
            default -> Duration.ofMinutes(loginTtlMinutes); // login OTP
        };
    }
}