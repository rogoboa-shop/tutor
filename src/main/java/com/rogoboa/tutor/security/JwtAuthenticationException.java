package com.rogoboa.tutor.security;

// ============ Custom Exception ============
public class JwtAuthenticationException extends RuntimeException {
    public JwtAuthenticationException(String message) {
        super(message);
    }
}
