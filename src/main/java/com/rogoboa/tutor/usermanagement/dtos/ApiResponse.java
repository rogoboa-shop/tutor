package com.rogoboa.tutor.usermanagement.dtos;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.LocalDateTime;

@JsonInclude(JsonInclude.Include.NON_NULL) // Hides fields that are null in the JSON output
public record ApiResponse<T>(
        boolean success,
        String message,
        T data,
        LocalDateTime timestamp
) {
    // Convenience constructor for success
    public ApiResponse(boolean success, String message, T data) {
        this(success, message, data, LocalDateTime.now());
    }

    // Convenience constructor for errors (where data is null)
    public ApiResponse(boolean success, String message) {
        this(success, message, null, LocalDateTime.now());
    }
}