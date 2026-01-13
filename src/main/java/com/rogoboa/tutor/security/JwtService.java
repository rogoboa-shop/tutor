package com.rogoboa.tutor.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Slf4j
@Service
public class JwtService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final SecretKey signingKey;

    @Value("${application.security.jwt.secret-key}")
    private String secret;

    @Value("${application.security.jwt.expiration}") // Default 1 hour
    private long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration:604800000}") // Default 7 days
    private long refreshExpiration;

    public JwtService(RedisTemplate<String, Object> redisTemplate, @Value("${application.security.jwt.secret-key}") String secret) {
        this.redisTemplate = redisTemplate;
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
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

    public UUID extractUserId(String token) {
        String userId = extractClaim(token, claims -> claims.get("userId", String.class));
        return UUID.fromString(userId);
    }

    public String extractUserType(String token) {
        return extractClaim(token, claims -> claims.get("userType", String.class));
    }

    // Update generateTokenPair to match your TokenPair class
    public TokenPair generateTokenPair(UUID userId, String email, String userType) {
        String accessToken = generateToken(userId, email, userType);
        String refreshToken = generateRefreshToken(email); // Typically refresh tokens don't need claims

        return new TokenPair(accessToken, refreshToken, jwtExpiration);
    }

    /**
     * Generate refresh token
     */
    public String generateRefreshToken(String email) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "refresh");
        String refreshToken = createToken(claims, email, refreshExpiration);

        // Store refresh token in Redis
        String redisKey = "refresh_token:" + email;
        redisTemplate.opsForValue().set(
                redisKey,
                refreshToken,
                Duration.ofMillis(refreshExpiration)
        );

        return refreshToken;
    }

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

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

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
        final String tokenEmail = extractEmail(token);
        boolean isValid = tokenEmail.equals(email) && !isTokenExpired(token);

        // Check if token is blacklisted
        if (isValid) {
            isValid = !isTokenBlacklisted(token);
        }

        return isValid;
    }

    public void blacklistToken(String token) {
        try {
            Date expiration = extractExpiration(token);
            long ttl = expiration.getTime() - System.currentTimeMillis();

            if (ttl > 0) {
                String redisKey = "blacklist:token:" + token;
                // The JSON serializer will handle "blacklisted" as a JSON string
                redisTemplate.opsForValue().set(
                        redisKey,
                        "blacklisted",
                        Duration.ofMillis(ttl)
                );
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
        String redisKey = "blacklist:token:" + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(redisKey));
    }

    /**
     * Revoke refresh token
     */
    public void revokeRefreshToken(String email) {
        String redisKey = "refresh_token:" + email;
        redisTemplate.delete(redisKey);
        log.info("Refresh token revoked for: {}", email);
    }

    /**
     * Validate refresh token
     */
    public boolean isRefreshTokenValid(String token, String email) {
        String redisKey = "refresh_token:" + email;

        // Get the object from Redis
        Object storedTokenObj = redisTemplate.opsForValue().get(redisKey);

        if (storedTokenObj == null) {
            log.warn("Refresh token not found in Redis for user: {}", email);
            return false;
        }

        String storedToken = storedTokenObj.toString();

        // Check 1: Does the token match what we have in Redis?
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
     * Generate token pair (access + refresh)
     */
    /*public TokenPair generateTokenPair(UUID userId, String email, String userType) {
        String accessToken = generateAccessToken(userId, email, userType);
        String refreshToken = generateRefreshToken(userId, email);

        return new TokenPair(accessToken, refreshToken, expiration);
    }*/
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

    public String getAccessToken() { return accessToken; }
    public String getRefreshToken() { return refreshToken; }
    public long getExpiresIn() { return expiresIn; }
}

