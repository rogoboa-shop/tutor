package com.rogoboa.tutor.security.otp;

import java.security.SecureRandom;

public class OTPGenerator {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final int OTP_LENGTH = 6;

    public static String generateNumericOTP() {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < OTP_LENGTH; i++) {
            otp.append(secureRandom.nextInt(10)); // digits 0-9
        }
        return otp.toString();
    }
}
