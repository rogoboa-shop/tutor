package com.rogoboa.tutor.usermanagement.dtos;

// UpdateProfileRequest.java
public record UpdateProfileRequest(
        String fullName,
        String bio,
        String schoolName,
        String grade,
        String profilePictureUrl
) {}
