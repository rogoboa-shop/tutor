package com.rogoboa.tutor.usermanagement.dtos;

import com.rogoboa.tutor.usermanagement.ContactType;

import java.util.UUID;

// ContactResponse.java
public record ContactResponse(
        UUID id,
        ContactType type,
        String value,
        boolean verified
) {}
