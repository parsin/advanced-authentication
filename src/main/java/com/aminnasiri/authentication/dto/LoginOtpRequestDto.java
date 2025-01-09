package com.aminnasiri.authentication.dto;

import lombok.Data;

@Data
public class LoginOtpRequestDto {
    private String username;
    private int otpCode;
    private String ip;
}
