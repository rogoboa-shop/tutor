package com.rogoboa.tutor.security.otp;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.rogoboa.tutor.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Service to manage blacklisted JWT tokens (for logout functionality)
 * Uses Caffeine in-memory cache instead of Redis for stateless token management
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final JwtService jwtService;

    private static final String BLACKLIST_PREFIX = "jwt:blacklist:";

    // Caffeine cache with expiration based on JWT token expiry
    private final Cache<String, String> blacklistCache = Caffeine.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS) // Max JWT lifetime
            .maximumSize(100_000) // Adjust based on expected load
            .build();

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
                // Store in Caffeine cache with expiration timestamp
                blacklistCache.put(key, String.valueOf(expirationDate.getTime()));
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
            String expirationStr = blacklistCache.getIfPresent(key);

            if (expirationStr == null) {
                return false;
            }

            // Double-check if the blacklist entry has expired
            long expirationTime = Long.parseLong(expirationStr);
            if (System.currentTimeMillis() > expirationTime) {
                blacklistCache.invalidate(key);
                return false;
            }

            return true;
        } catch (Exception e) {
            log.error("Failed to check token blacklist: {}", e.getMessage());
            // Fail open - allow the token if there's an error
            return false;
        }
    }

    /**
     * Remove token from blacklist (mainly for testing)
     */
    public void removeFromBlacklist(String token) {
        String key = BLACKLIST_PREFIX + token;
        blacklistCache.invalidate(key);
        log.info("Token removed from blacklist");
    }

    /**
     * Clear all blacklisted tokens (mainly for testing/admin purposes)
     */
    public void clearBlacklist() {
        blacklistCache.invalidateAll();
        log.info("All tokens cleared from blacklist");
    }

    /**
     * Get current blacklist size
     */
    public long getBlacklistSize() {
        return blacklistCache.estimatedSize();
    }

    /**
     * Blacklist all tokens for a user (e.g., when password is changed)
     * Note: This is a placeholder - true implementation would require maintaining
     * a user-to-tokens mapping, which adds state. For stateless approach, consider
     * including a "version" claim in JWT and incrementing it on password change.
     */
    public void blacklistAllUserTokens(String userId) {
        log.info("Request to blacklist all tokens for user: {}", userId);
        log.warn("Blacklisting all user tokens requires stateful tracking. " +
                "Consider using JWT version claims for true stateless invalidation.");
    }
}