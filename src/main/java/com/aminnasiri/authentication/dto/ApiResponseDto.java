package com.aminnasiri.authentication.dto;

import lombok.Data;

@Data
public class ApiResponseDto <T> {
    private boolean success;
    private String message;
    private T data;
    private String error;

    public ApiResponseDto(boolean success, String message, T data, String error) {
        this.success = success;
        this.message = message;
        this.data = data;
        this.error = error;
    }

}
