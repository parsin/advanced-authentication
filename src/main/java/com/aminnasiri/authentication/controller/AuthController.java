package com.aminnasiri.authentication.controller;

import com.aminnasiri.authentication.dto.*;
import com.aminnasiri.authentication.exception.TooManyRequestsException;
import com.aminnasiri.authentication.exception.UnauthorizedUserException;
import com.aminnasiri.authentication.service.AuthService;
import com.aminnasiri.authentication.service.UserService;
import com.aminnasiri.authentication.util.HttpUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;


    @PostMapping("/register")
    public ResponseEntity<ApiResponseDto<?>> register(@RequestBody UserDto userDto, HttpServletRequest request) {
        try {
            userDto.setIp(HttpUtils.getRequestIP(request));
            JwtResponseDto jwtResponseDto = authService.registerUser(userDto);
            ApiResponseDto<?> response = new ApiResponseDto<>(true, "User registered and authenticated successfully",
                    jwtResponseDto, null);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (Exception e) {
            ApiResponseDto<Void> response = new ApiResponseDto<>(false, "Registration failed", null, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    @PostMapping("/login-with-password")
    public ResponseEntity<ApiResponseDto<?>> loginWithPassword(@RequestBody LoginPasswordRequestDto loginRequest,HttpServletRequest request) {
        try{
            loginRequest.setIp(HttpUtils.getRequestIP(request));
            JwtResponseDto jwtResponseDto = authService.loginWithPassword(loginRequest);
            ApiResponseDto<JwtResponseDto> response = new ApiResponseDto<>(true, "Login successful", jwtResponseDto, null);
            return ResponseEntity.ok(response);
        }catch (AuthenticationException e) {
            ApiResponseDto<Void> response = new ApiResponseDto<>(false, "Authentication failed", null, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    @PostMapping("/login-with-otp")
    public ResponseEntity<ApiResponseDto<?>> loginWithOtp(@RequestBody LoginOtpRequestDto loginOtpRequestDto, HttpServletRequest request){
        try{
            loginOtpRequestDto.setIp(HttpUtils.getRequestIP(request));
            JwtResponseDto jwtResponseDto = authService.loginWithOtp(loginOtpRequestDto);
            ApiResponseDto<JwtResponseDto> response = new ApiResponseDto<>(true, "Login successful", jwtResponseDto, null);
            return ResponseEntity.ok(response);
        }catch (AuthenticationException e) {
            ApiResponseDto<Void> response = new ApiResponseDto<>(false, "Authentication failed", null, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponseDto<?>> refreshToken(@RequestBody RefreshTokenDto refreshToken) {
        try{
            JwtResponseDto jwtResponseDto = authService.validateAndIssueNewRefreshToken(refreshToken.getRefreshToken());
            ApiResponseDto<JwtResponseDto> response = new ApiResponseDto<>(true,
                    "New refresh token was generated", jwtResponseDto, null);
            return ResponseEntity.ok(response);
        }catch (AuthenticationException e) {
            ApiResponseDto<Void> response = new ApiResponseDto<>(false,
                    "Invalid or expired refresh token. Please log in again.", null, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    // Call this method to get otp, in the first time isResend is false, otherwise is true
    @PostMapping("/otp")
    public ResponseEntity<ApiResponseDto<?>> sendOtp(@Valid @RequestBody OtpRequestDto otpRequestDto,
                                          HttpServletRequest request){
        try {
            otpRequestDto.setIp(HttpUtils.getRequestIP(request));
            String userFlow = authService.generateAndSendOtp(otpRequestDto);
            ApiResponseDto<String> response = new ApiResponseDto<>(true, "OTP sent", userFlow, null);
            return ResponseEntity.ok(response);
        }catch (TooManyRequestsException e){
            ApiResponseDto<Void> response = new ApiResponseDto<>(false, "Too many requests.", null, e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
        }
    }
}
