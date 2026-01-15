package com.rogoboa.tutor.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@Slf4j
@Service
public class JwtService {

    private final SecretKey signingKey;
    private final Cache<String, String> tokenBlacklistCache;
    private final Cache<String, String> refreshTokenCache;

    @Value("${application.security.jwt.secret-key}")
    private String secret;

    @Value("${application.security.jwt.expiration}") // Default 1 hour
    private long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration:604800000}") // Default 7 days
    private long refreshExpiration;

    public JwtService(@Value("${application.security.jwt.secret-key}") String secret) {
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

        // Initialize blacklist cache
        this.tokenBlacklistCache = Caffeine.newBuilder()
                .expireAfterWrite(24, TimeUnit.HOURS) // Max token lifetime
                .maximumSize(100_000)
                .build();

        // Initialize refresh token cache
        this.refreshTokenCache = Caffeine.newBuilder()
                .expireAfterWrite(7, TimeUnit.DAYS) // Max refresh token lifetime
                .maximumSize(50_000)
                .build();
    }

    /**
     * Generate access token
     */
    public String generateToken(UUID userId, String email, String userType) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId.toString());
        claims.put("userType", userType);
        return createToken(claims, email, jwtExpiration);
    }

    /**
     * Extract userId from token
     */
    public UUID extractUserId(String token) {
        String userId = extractClaim(token, claims -> claims.get("userId", String.class));
        return UUID.fromString(userId);
    }

    /**
     * Extract userType from token
     */
    public String extractUserType(String token) {
        return extractClaim(token, claims -> claims.get("userType", String.class));
    }

    /**
     * Generate token pair (access + refresh)
     */
    public TokenPair generateTokenPair(UUID userId, String email, String userType) {
        String accessToken = generateToken(userId, email, userType);
        String refreshToken = generateRefreshToken(email);

        return new TokenPair(accessToken, refreshToken, jwtExpiration);
    }

    /**
     * Generate refresh token
     */
    public String generateRefreshToken(String email) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "refresh");
        String refreshToken = createToken(claims, email, refreshExpiration);

        // Store refresh token in Caffeine cache with expiration timestamp
        String cacheKey = "refresh_token:" + email;
        Date expirationDate = extractExpiration(refreshToken);
        String value = refreshToken + ":" + expirationDate.getTime();

        refreshTokenCache.put(cacheKey, value);
        log.debug("Refresh token cached for: {}", email);

        return refreshToken;
    }

    /**
     * Create JWT token
     */
    private String createToken(Map<String, Object> claims, String subject, long expiration) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Extract email from token
     */
    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extract expiration date from token
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extract specific claim from token
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extract all claims from token
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Check if token is expired
     */
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Validate token
     */
    public Boolean isTokenValid(String token, String email) {
        try {
            final String tokenEmail = extractEmail(token);
            boolean isValid = tokenEmail.equals(email) && !isTokenExpired(token);

            // Check if token is blacklisted
            if (isValid) {
                isValid = !isTokenBlacklisted(token);
            }

            return isValid;
        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Blacklist token (for logout)
     */
    public void blacklistToken(String token) {
        try {
            Date expiration = extractExpiration(token);
            long ttl = expiration.getTime() - System.currentTimeMillis();

            if (ttl > 0) {
                String cacheKey = "blacklist:token:" + token;
                // Store with expiration timestamp
                tokenBlacklistCache.put(cacheKey, String.valueOf(expiration.getTime()));
                log.info("Token blacklisted successfully for {}ms", ttl);
            }
        } catch (Exception e) {
            log.error("Error blacklisting token", e);
        }
    }

    /**
     * Check if token is blacklisted
     */
    public boolean isTokenBlacklisted(String token) {
        try {
            String cacheKey = "blacklist:token:" + token;
            String expirationStr = tokenBlacklistCache.getIfPresent(cacheKey);

            if (expirationStr == null) {
                return false;
            }

            // Double-check expiration
            long expirationTime = Long.parseLong(expirationStr);
            if (System.currentTimeMillis() > expirationTime) {
                tokenBlacklistCache.invalidate(cacheKey);
                return false;
            }

            return true;
        } catch (Exception e) {
            log.error("Error checking token blacklist: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Revoke refresh token
     */
    public void revokeRefreshToken(String email) {
        String cacheKey = "refresh_token:" + email;
        refreshTokenCache.invalidate(cacheKey);
        log.info("Refresh token revoked for: {}", email);
    }

    /**
     * Validate refresh token
     */
    public boolean isRefreshTokenValid(String token, String email) {
        String cacheKey = "refresh_token:" + email;

        // Get the cached value
        String cachedValue = refreshTokenCache.getIfPresent(cacheKey);

        if (cachedValue == null) {
            log.warn("Refresh token not found in cache for user: {}", email);
            return false;
        }

        // Parse cached value (format: "token:expirationTimestamp")
        String[] parts = cachedValue.split(":", 2);
        if (parts.length != 2) {
            log.error("Invalid cached refresh token format for user: {}", email);
            return false;
        }

        String storedToken = parts[0];
        long expirationTime = Long.parseLong(parts[1]);

        // Check if expired
        if (System.currentTimeMillis() > expirationTime) {
            refreshTokenCache.invalidate(cacheKey);
            log.warn("Refresh token expired for user: {}", email);
            return false;
        }

        // Check 1: Does the token match what we have in cache?
        // Check 2: Is the token itself valid (signature/expiration)?
        return storedToken.equals(token) && isTokenValid(token, email);
    }

    /**
     * Get token expiration in milliseconds
     */
    public long getTokenExpiration() {
        return jwtExpiration;
    }

    /**
     * Get refresh token expiration in milliseconds
     */
    public long getRefreshTokenExpiration() {
        return refreshExpiration;
    }

    /**
     * Clear all blacklisted tokens (for testing)
     */
    public void clearBlacklist() {
        tokenBlacklistCache.invalidateAll();
        log.info("Token blacklist cleared");
    }

    /**
     * Clear all refresh tokens (for testing)
     */
    public void clearRefreshTokens() {
        refreshTokenCache.invalidateAll();
        log.info("All refresh tokens cleared");
    }

    /**
     * Get blacklist cache size
     */
    public long getBlacklistSize() {
        return tokenBlacklistCache.estimatedSize();
    }

    /**
     * Get refresh token cache size
     */
    public long getRefreshTokenCacheSize() {
        return refreshTokenCache.estimatedSize();
    }
}

// ============ Token Pair Response ============
class TokenPair {
    private String accessToken;
    private String refreshToken;
    private long expiresIn;

    public TokenPair(String accessToken, String refreshToken, long expiresIn) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public long getExpiresIn() {
        return expiresIn;
    }
}