package com.rogoboa.tutor.security.otp;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class OTPVerificationResponse {
    private boolean valid;
    private String message;
    private long timestamp;

    public OTPVerificationResponse(boolean valid, String message) {
        this.valid = valid;
        this.message = message;
        this.timestamp = System.currentTimeMillis();
    }

    public boolean isValid() { return valid; }
    public String getMessage() { return message; }
    public long getTimestamp() { return timestamp; }
}
