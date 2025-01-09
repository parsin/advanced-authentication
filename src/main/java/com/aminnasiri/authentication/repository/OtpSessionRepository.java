package com.aminnasiri.authentication.repository;

import com.aminnasiri.authentication.entity.OtpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.concurrent.TimeUnit;

@Repository
@RequiredArgsConstructor
public class OtpSessionRepository {

    @Value("${redis.otp-session.duration}")
    private long otpSessionDuration;
    @Value("${redis.otp-session-penalty.duration}")
    private long otpSessionPenaltyDuration;

    private final String REDIS_OTP_SESSION_PREFIX = "otp_session:";
    private final String REDIS_OTP_SESSION_PENALTY_PREFIX = "otp_session_penalty:";

    private final RedisTemplate<String, Object> redisTemplate;

    public OtpSession findOtpSessionByUsernameAndIp(String username, String ip){
        String sessionKey = REDIS_OTP_SESSION_PREFIX + username+"-"+ip;
        return (OtpSession)redisTemplate.opsForValue().get(sessionKey);
    }

    public String findOtpSessionPenalty(String penalty){
        String sessionPenaltyKey = REDIS_OTP_SESSION_PENALTY_PREFIX + penalty;
        return (String)redisTemplate.opsForValue().get(sessionPenaltyKey);
    }

    public void saveOtpSession (OtpSession otpSession){
        String sessionKey = REDIS_OTP_SESSION_PREFIX + otpSession.getUsername()+"-"+otpSession.getIp();
        redisTemplate.opsForValue().set(sessionKey, otpSession, otpSessionDuration, TimeUnit.MILLISECONDS);
    }

    public void saveSessionPenalty(String penalty,String username){
        String sessionPenaltyKey = REDIS_OTP_SESSION_PENALTY_PREFIX + penalty;
        redisTemplate.opsForValue().set(sessionPenaltyKey, username, otpSessionPenaltyDuration, TimeUnit.MILLISECONDS);
    }

    public Long findOtpSessionExpireTime(String username, String ip) {
        String sessionKey = REDIS_OTP_SESSION_PREFIX + username+"-"+ip;
        return redisTemplate.getExpire(sessionKey, TimeUnit.MILLISECONDS);
    }

    public void invalidateOtpSession(String username, String ip) {
        String sessionKey = REDIS_OTP_SESSION_PREFIX + username+"-"+ip;
        redisTemplate.delete(sessionKey);
    }
}
