package com.aminnasiri.authentication.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class OtpRequestDto {

    private String username;
    private boolean isRepetitiveRequest;
    String ip;
}
