package com.aminnasiri.authentication.dto;

import lombok.Data;

@Data
public class UserDto {
    String username; // Username can store phone number or email address
    String password;
    String firstName;
    String lastName;
    int otpCode;
    String ip;
}
