package com.aminnasiri.authentication.service;

import com.aminnasiri.authentication.dto.*;
import com.aminnasiri.authentication.entity.OtpSession;
import com.aminnasiri.authentication.entity.Role;
import com.aminnasiri.authentication.entity.Token;
import com.aminnasiri.authentication.entity.User;
import com.aminnasiri.authentication.exception.TooManyRequestsException;
import com.aminnasiri.authentication.exception.UnauthorizedUserException;
import com.aminnasiri.authentication.repository.OtpSessionRepository;
import com.aminnasiri.authentication.repository.TokenRepository;
import com.aminnasiri.authentication.util.JwtUtils;
import io.jsonwebtoken.Claims;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Random;
import java.util.Set;

@Transactional
@Service
@RequiredArgsConstructor
public class AuthService {

    private final OtpSessionRepository otpSessionRepository;
    private final TokenRepository tokenRepository;
    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;
    private final MyUserDetailsService userDetailsService;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Value("${otp-request.limit}")
    private int MAX_OTP_REQUESTS_PER_HOUR;

    // The main method for authentication
    private JwtResponseDto authenticate (String username, String password, String ip) {
        Authentication authentication = null;
        if(password == null){ // No password needed for OTP-based authentication
            authentication = new UsernamePasswordAuthenticationToken(username,
                password,
                Collections.emptySet()
        );
        }else{
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        // Invalidate otp session to prevent form using otp again
        otpSessionRepository.invalidateOtpSession(username, ip);
        // Invalidate old tokens, generate new ones and store them
        Token accessToken = this.invalidateAndGenerateNewAccessToken(username);
        Token refreshToken = this.invalidateAndGenerateNewRefreshToken(username);
        return new JwtResponseDto(accessToken.getToken(), refreshToken.getToken());
    }

    public JwtResponseDto loginWithPassword(LoginPasswordRequestDto loginPasswordRequestDto) {
        return this.authenticate(loginPasswordRequestDto.getUsername(), loginPasswordRequestDto.getPassword(), loginPasswordRequestDto.getIp());
    }

    public JwtResponseDto loginWithOtp(LoginOtpRequestDto loginOtpRequestDto) {
        // Retrieve user details from the database or other source
        UserDetails userDetails = userDetailsService.loadUserByUsername(loginOtpRequestDto.getUsername());
        if (userDetails == null) {
            throw new UsernameNotFoundException("User not found");
        }
        // Validate the OTP
        OtpSession otpSession = otpSessionRepository.findOtpSessionByUsernameAndIp(loginOtpRequestDto.getUsername(), loginOtpRequestDto.getIp());
        if(otpSession == null || otpSession.getOtpCode() != loginOtpRequestDto.getOtpCode()){
            throw new BadCredentialsException("Invalid or expired token");
        }
        // If OTP is valid, authenticate the user and return tokens
        return this.authenticate(userDetails.getUsername(),null,loginOtpRequestDto.getIp());
    }

    public JwtResponseDto validateAndIssueNewRefreshToken (String refreshTokenString){
        // Extract username from the refresh token
        String username = jwtUtils.getClaimFromToken(refreshTokenString, Claims::getSubject);
        // Validate the refresh token
        Token storedToken = tokenRepository.findRefreshTokenByUsername(username);
        if (storedToken == null || storedToken.getExpiryTime() < System.currentTimeMillis() ||
                !storedToken.getToken().equals(refreshTokenString)) {
            throw new UnauthorizedUserException("Invalid or expired refresh token");
        }

        // Invalidate old tokens, generate new ones and store them
        Token newAccessToken = this.invalidateAndGenerateNewAccessToken(username);
        Token newRefreshToken = this.invalidateAndGenerateNewRefreshToken(username);

        return new JwtResponseDto(newAccessToken.getToken(), newRefreshToken.getToken());
    }

    private Token invalidateAndGenerateNewAccessToken(String username) {
        // invalidate old access token to prevent using it again.
        tokenRepository.invalidateAccessTokenByUsername(username);
        // Generate new access token
        Token newAccessToken = jwtUtils.generateAccessToken(username, "ROLE_USER");
        // Save new tokens in Redis
        tokenRepository.saveAccessToken(newAccessToken);
        return newAccessToken;
    }

    private Token invalidateAndGenerateNewRefreshToken(String username) {
        // invalidate old refresh token to prevent using it again.
        tokenRepository.invalidateRefreshTokenByUsername(username);
        // Generate new refresh token
        Token newRefreshToken = jwtUtils.generateRefreshToken(username);
        // Save new tokens in Redis
        tokenRepository.saveRefreshToken(newRefreshToken);
        return newRefreshToken;
    }

    public String generateAndSendOtp(OtpRequestDto otpRequestDto) {

        // Rate-limit validation, if combination phone number and ip exceeded then ban user
        this.checkOtpRequestRateLimit(otpRequestDto);

        //So user has authority to ask otp, then get OtpSession from redis if exist
        OtpSession otpSession = otpSessionRepository.findOtpSessionByUsernameAndIp(otpRequestDto.getUsername(), otpRequestDto.getIp());

        // If otpSession doesn't exist, create one, generate otp and send it to the user
        if(otpSession == null){
            // Create a new session if it doesn't exist
            otpSession = new OtpSession();
            otpSession.setVerificationCount(1);
            otpSession.setOtpCode(generateOtpCode());
            otpSession.setUsername(otpRequestDto.getUsername());
            otpSession.setIp(otpRequestDto.getIp());
            this.sendOTP(otpSession);
            otpSessionRepository.saveOtpSession(otpSession);
            User user = userService.getUser(otpRequestDto.getUsername());
            // If the user doesn't exist, return "Sign up" to the client. The next step is registration. If the user exists, return "Sign in".
            if(user == null){
                return "Sign up";
            }else
                return "Sign in";
        }

        /* If otpSession exists, check verification count,
        adjust it and generate new otp code and send it to the user */
        if (otpSession.getVerificationCount() >= (MAX_OTP_REQUESTS_PER_HOUR - 1)) {
            //Generate a new code and send it to the user, but insert penalty session into the Redis to prevent further requests.
            String penaltyKey = otpRequestDto.getUsername()+"-"+otpRequestDto.getIp();
            otpSessionRepository.saveSessionPenalty(penaltyKey, otpRequestDto.getUsername());
            otpSession.setOtpCode(generateOtpCode());
            sendOTP(otpSession);
            otpSession.setVerificationCount(otpSession.getVerificationCount() + 1);
            otpSessionRepository.saveOtpSession(otpSession);
            return "Sign in";
        }

        Long otpExpirationTtl = otpSessionRepository.findOtpSessionExpireTime(otpRequestDto.getUsername(), otpRequestDto.getIp());
        // It is checked that there are 90 seconds remaining from the validity of the otp code to use.
        // It is useful when use send opt via phone number
        if (otpExpirationTtl != null && otpExpirationTtl < 90) {
            otpSession.setOtpCode(generateOtpCode());
        }
        otpSession.setVerificationCount(otpSession.getVerificationCount() + 1);
        this.sendOTP(otpSession);
        otpSessionRepository.saveOtpSession(otpSession);
        return "Sign in";
    }

    public JwtResponseDto registerUser(UserDto userDto) throws DataIntegrityViolationException{
        // Get otp session from Redis
        OtpSession otpSession = otpSessionRepository.findOtpSessionByUsernameAndIp(userDto.getUsername(), userDto.getIp());
        // If otp session doesn't exist, session is expired
        if(otpSession == null || otpSession.getOtpCode() != userDto.getOtpCode()){
            throw new UnauthorizedUserException("Invalid or expired token");
        }

        User user = new User();
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        user.setUsername(userDto.getUsername());
        user.setFirstName(userDto.getFirstName());
        user.setLastName(userDto.getLastName());
        user.setRoles(Collections.emptySet());
        try {
            userService.save(user);
            // Authenticate the user and return tokens
            return this.authenticate(userDto.getUsername(), userDto.getPassword(),userDto.getIp());
        }catch (DataIntegrityViolationException e){
            throw new DataIntegrityViolationException("User already exists");
        }
    }
    /*
    This method checks that a user with specific ip can ask for an otp just 5 times.
    The key uses ip to make it unique
    If attacker uses different phone numbers, real users are not banned due to the ip
     */
    private void checkOtpRequestRateLimit(OtpRequestDto otpRequestDto){
        String penaltyKey = otpRequestDto.getUsername()+"-"+otpRequestDto.getIp();
        if(otpSessionRepository.findOtpSessionPenalty(penaltyKey) != null)
            throw new TooManyRequestsException("Maximum OTP requests exceeded for this hour.");
    }

    private void sendOTP(OtpSession otpSession) {
        // Send otp
    }

    public int generateOtpCode() {
        Random r = new Random();
        return r.nextInt(9000)+1000;
    }

}
