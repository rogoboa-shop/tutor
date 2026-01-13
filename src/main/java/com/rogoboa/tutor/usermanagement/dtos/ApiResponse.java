package com.rogoboa.tutor.usermanagement.dtos;

// ApiResponse.java (Generic wrapper for all responses)
public record ApiResponse<T>(
        boolean success,
        String message,
        T data
) {}
