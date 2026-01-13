package com.rogoboa.tutor.usermanagement.dtos;

// AuthResponse.java
public record AuthResponse(
        String accessToken,
        String refreshToken,
        UserResponse user
) {}
