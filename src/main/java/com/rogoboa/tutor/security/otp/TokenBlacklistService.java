package com.rogoboa.tutor.security.otp;

import com.rogoboa.tutor.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Date;

/**
 * Service to manage blacklisted JWT tokens (for logout functionality)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final StringRedisTemplate redisTemplate;
    private final JwtService jwtService;

    private static final String BLACKLIST_PREFIX = "jwt:blacklist:";

    /**
     * Add token to blacklist (when user logs out)
     */
    public void blacklistToken(String token) {
        try {
            String key = BLACKLIST_PREFIX + token;

            // Calculate remaining TTL for the token
            Date expirationDate = jwtService.extractExpiration(token);
            long ttl = expirationDate.getTime() - System.currentTimeMillis();

            if (ttl > 0) {
                // Store in Redis with TTL matching token expiration
                redisTemplate.opsForValue().set(
                        key,
                        "blacklisted",
                        Duration.ofMillis(ttl)
                );
                log.info("Token blacklisted successfully with TTL: {} ms", ttl);
            }
        } catch (Exception e) {
            log.error("Failed to blacklist token: {}", e.getMessage());
        }
    }

    /**
     * Check if token is blacklisted
     */
    public boolean isTokenBlacklisted(String token) {
        try {
            String key = BLACKLIST_PREFIX + token;
            Boolean exists = redisTemplate.hasKey(key);
            return Boolean.TRUE.equals(exists);
        } catch (Exception e) {
            log.error("Failed to check token blacklist: {}", e.getMessage());
            // Fail open - allow the token if Redis is down
            return false;
        }
    }

    /**
     * Remove token from blacklist (mainly for testing)
     */
    public void removeFromBlacklist(String token) {
        String key = BLACKLIST_PREFIX + token;
        redisTemplate.delete(key);
        log.info("Token removed from blacklist");
    }

    /**
     * Blacklist all tokens for a user (e.g., when password is changed)
     */
    public void blacklistAllUserTokens(String userId) {
        // This would require maintaining a list of active tokens per user
        // For simplicity, we'll just log it
        log.info("Request to blacklist all tokens for user: {}", userId);
        // Implementation would depend on your token management strategy
    }
}
