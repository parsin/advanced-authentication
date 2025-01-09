package com.aminnasiri.authentication.entity;

import lombok.Data;

// This class stores OTP session in Redis
@Data
public class OtpSession {
    private String username;
    private int otpCode;
    private int verificationCount;
    private String ip;
}
