package com.rogoboa.tutor.security.otp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;

@Service
public class OTPCacheService {

    private final StringRedisTemplate redisTemplate;
    private final SecureRandom secureRandom = new SecureRandom();
    private static final Duration OTP_TTL = Duration.ofMinutes(5);

    @Value("${otp.ttl.login:5}")
    private long loginTtlMinutes;
    @Value("${otp.ttl.password_reset:15}")
    private long passwordResetTtlMinutes;
    @Value("${otp.ttl.email_verification:10}")
    private long emailVerificationTtlMinutes;


    @Autowired
    public OTPCacheService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * Generate and store OTP with expiration.
     */
    public String generateOTP(String key, String purpose) {
        String otp = OTPGenerator.generateNumericOTP();
        String redisKey = buildRedisKey(purpose, key);
        redisTemplate.opsForValue().set(redisKey, otp, getTtlForPurpose(purpose));
        return otp;
    }

    /**
     * Validate and consume OTP (single-use) in a constant-time manner.
     */
    public boolean validateOTP(String key, String purpose, String otp) {
        String redisKey = buildRedisKey(purpose, key);
        String cachedOtp = redisTemplate.opsForValue().get(redisKey);
        if (cachedOtp == null) return false;
        boolean isMatch = MessageDigest.isEqual(
                cachedOtp.getBytes(StandardCharsets.UTF_8),
                otp.getBytes(StandardCharsets.UTF_8)
        );
        if (isMatch) redisTemplate.delete(redisKey);
        return isMatch;
    }

    public void invalidateOTP(String key, String purpose) {
        redisTemplate.delete(buildRedisKey(purpose, key));
    }

    public String requestNewOTP(String key, String purpose) {
        invalidateOTP(key, purpose);
        return generateOTP(key, purpose);
    }

    // Add this method to your OTPCacheService class:

    /**
     * Get cached OTP without consuming it (for verification preview)
     */
    public String getCachedOTP(String redisKey) {
        return redisTemplate.opsForValue().get(redisKey);
    }

    private String buildRedisKey(String purpose, String key) {
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

