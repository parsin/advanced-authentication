package com.aminnasiri.authentication.repository;

import com.aminnasiri.authentication.entity.OtpSession;
import com.aminnasiri.authentication.entity.Token;
import org.springframework.beans.factory.annotation.Value;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.concurrent.TimeUnit;


@Repository
@RequiredArgsConstructor
public class TokenRepository {

//    @Value("${jwt.refresh-token-rate-limit}")
//    private long refreshTokenRateLimit;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;
    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;
    @Value("${redis.otp-session-penalty.duration}")
    private long otpSessionPenaltyDuration;

    private final String REDIS_REFRESH_TOKEN_PREFIX = "refresh_token:";
    private final String REDIS_ACCESS_TOKEN_PREFIX = "access_token:";
    private final String REDIS_REFRESH_TOKEN_PENALTY_PREFIX = "otp_refresh_token_penalty:";

    private final RedisTemplate<String, Object> redisTemplate;

    public Token findRefreshTokenByUsername(String username){
        String refreshTokenKey = REDIS_REFRESH_TOKEN_PREFIX + username;
        return (Token)redisTemplate.opsForValue().get(refreshTokenKey);
    }

    public void invalidateRefreshTokenByUsername(String username) {
        String refreshTokenKey = REDIS_REFRESH_TOKEN_PREFIX + username;
        redisTemplate.delete(refreshTokenKey);
    }

    public void saveRefreshToken (Token refreshToken){
        String refreshTokenKey = REDIS_REFRESH_TOKEN_PREFIX + refreshToken.getUsername();
        redisTemplate.opsForValue().set(refreshTokenKey, refreshToken, refreshTokenExpiration, TimeUnit.MILLISECONDS);
    }

    public void saveRefreshTokenPenalty(String penalty,String username){
        String sessionPenaltyKey = REDIS_REFRESH_TOKEN_PENALTY_PREFIX + penalty;
        redisTemplate.opsForValue().set(sessionPenaltyKey, username, otpSessionPenaltyDuration, TimeUnit.MILLISECONDS);
    }

    public String findRefreshTokenPenalty(String penalty){
        String sessionPenaltyKey = REDIS_REFRESH_TOKEN_PENALTY_PREFIX + penalty;
        return (String)redisTemplate.opsForValue().get(sessionPenaltyKey);
    }

    public Token findAccessTokenByUsername(String username){
        String accessTokenKey = REDIS_ACCESS_TOKEN_PREFIX + username;
        return (Token)redisTemplate.opsForValue().get(accessTokenKey);
    }

    public void invalidateAccessTokenByUsername(String username) {
        String accessTokenKey = REDIS_ACCESS_TOKEN_PREFIX + username;
        redisTemplate.delete(accessTokenKey);
    }

    public void saveAccessToken (Token accessToken){
        String accessTokenKey = REDIS_ACCESS_TOKEN_PREFIX + accessToken.getUsername();
        redisTemplate.opsForValue().set(accessTokenKey, accessToken, accessTokenExpiration, TimeUnit.MILLISECONDS);
    }

}
