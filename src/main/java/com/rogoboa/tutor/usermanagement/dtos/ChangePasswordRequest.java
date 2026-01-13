package com.rogoboa.tutor.usermanagement.dtos;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

// ChangePasswordRequest.java
public record ChangePasswordRequest(
        @NotBlank String oldPassword,
        @NotBlank @Size(min = 8) String newPassword
) {}