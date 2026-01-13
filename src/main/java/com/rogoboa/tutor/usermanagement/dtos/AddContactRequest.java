package com.rogoboa.tutor.usermanagement.dtos;

import com.rogoboa.tutor.usermanagement.ContactType;
import jakarta.validation.constraints.NotBlank;

// AddContactRequest.java
public record AddContactRequest(
        @NotBlank ContactType type,
        @NotBlank String value
) {}
