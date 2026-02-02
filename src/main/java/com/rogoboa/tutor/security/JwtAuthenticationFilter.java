package com.rogoboa.tutor.security;

import com.rogoboa.tutor.usermanagement.User;
import com.rogoboa.tutor.usermanagement.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.UUID;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    public JwtAuthenticationFilter(@Lazy JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        try {
            String jwt = extractJwtFromCookie(request, "access_token");

            if (StringUtils.hasText(jwt)) {
                // 1. Check Blacklist via JwtService
                if (jwtService.isTokenBlacklisted(jwt)) {
                    log.debug("Blacklisted token, skipping authentication");
                    filterChain.doFilter(request, response);
                    return;
                }

                // 2. Extract Data
                String email = jwtService.extractEmail(jwt);

                // 3. Validate Token structure and expiration
                if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    if (jwtService.isTokenValid(jwt, email)) {

                        UUID userId = jwtService.extractUserId(jwt);
                        String userType = jwtService.extractUserType(jwt);

                        // 4. Load User
                        User user = userRepository.findById(userId).orElse(null);

                        if (user != null && user.isActive()) {
                            UsernamePasswordAuthenticationToken authentication =
                                    new UsernamePasswordAuthenticationToken(
                                            user,
                                            null,
                                            Collections.singletonList(
                                                    new SimpleGrantedAuthority("ROLE_" + userType)
                                            )
                                    );

                            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                        }
                    }
                }
            }
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            log.debug("JWT expired, continuing unauthenticated");
        }
        catch (io.jsonwebtoken.JwtException e) {
            log.debug("Invalid JWT, continuing unauthenticated");
        }
        catch (Exception e) {
            log.error("Unexpected authentication error", e);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extract JWT from HTTP-only cookie
     */
    private String extractJwtFromCookie(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    /**
     * Skip JWT filter for public endpoints
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        // Don't skip if it's the /me endpoint
        if (path.equals("/api/auth/me")) {
            return false;
        }

        // Public endpoints that don't require authentication
        return path.startsWith("/api/auth/") ||
                path.startsWith("/api/banners/");
    }
}