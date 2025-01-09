package com.aminnasiri.authentication.dto;

import lombok.Data;

@Data
public class LoginPasswordRequestDto {
    private String username;
    private String password;
    private String ip;
}
