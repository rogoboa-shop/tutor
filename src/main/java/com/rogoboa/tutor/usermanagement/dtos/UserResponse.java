package com.rogoboa.tutor.usermanagement.dtos;

import java.util.UUID;

// UserResponse.java
public record UserResponse(
        UUID id,
        String fullName,
        String email,
        String role,
        String profilePictureUrl,
        boolean emailVerified
) {}