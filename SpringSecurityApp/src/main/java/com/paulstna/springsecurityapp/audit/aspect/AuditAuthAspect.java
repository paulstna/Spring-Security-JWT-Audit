package com.paulstna.springsecurityapp.audit.aspect;

import com.paulstna.springsecurityapp.audit.constants.MdcKeysConstants;
import com.paulstna.springsecurityapp.audit.enums.EventAction;
import com.paulstna.springsecurityapp.audit.enums.EventType;
import com.paulstna.springsecurityapp.auth.domain.LoginRequest;
import com.paulstna.springsecurityapp.auth.domain.RegisterRequest;
import com.paulstna.springsecurityapp.jwt.service.IJwtProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class AuditAuthAspect {

    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");
    private final IJwtProvider jwtProvider;

    @Pointcut("execution(public * com.paulstna.springsecurityapp.auth.service.AuthServiceImpl.login(..))")
    void login() {
    }

    @Pointcut("execution(public * com.paulstna.springsecurityapp.auth.service.AuthServiceImpl.register(..))")
    void register() {
    }

    @Pointcut("execution(public * com.paulstna.springsecurityapp.auth.service.AuthServiceImpl.refreshToken(..))")
    void refreshToken() {
    }

    @Pointcut("execution(public * com.paulstna.springsecurityapp.auth.service.AuthServiceImpl.logout(..))")
    void logout() {
    }


    @Before("login()")
    public void loginAttempt(JoinPoint jp) {
        LoginRequest req = extractArg(jp, LoginRequest.class, 0);
        String ip = extractArg(jp, String.class, 2);

        if (req == null) return;

        try {
            putBaseContext(req.getUsername(), ip);
            MDC.put(MdcKeysConstants.EVENT_TYPE, EventType.AUTH.name());
            MDC.put(MdcKeysConstants.EVENT_ACTION, EventAction.LOGIN_ATTEMPT.name());

            AUDIT.info("Login attempt for user: {}", req.getUsername());
        } finally {
            clearMdc();
        }
    }

    @AfterReturning("login()")
    public void loginSuccess(JoinPoint jp) {
        LoginRequest req = extractArg(jp, LoginRequest.class, 0);
        String ip = extractArg(jp, String.class, 2);

        if (req == null) return;

        try {
            putBaseContext(req.getUsername(), ip);
            MDC.put(MdcKeysConstants.EVENT_TYPE, EventType.AUTH.name());
            MDC.put(MdcKeysConstants.EVENT_ACTION, EventAction.LOGIN_SUCCESS.name());

            AUDIT.info("Login successful for user: {}", req.getUsername());
        } finally {
            clearMdc();
        }
    }

    @Before("register()")
    public void registerAttempt(JoinPoint jp) {
        RegisterRequest req = extractArg(jp, RegisterRequest.class, 0);
        String ip = extractArg(jp, String.class, 2);

        if (req == null) return;

        try {
            putBaseContext(req.getUsername(), ip);
            MDC.put(MdcKeysConstants.EVENT_TYPE, EventType.AUTH.name());
            MDC.put(MdcKeysConstants.EVENT_ACTION, EventAction.REGISTER_ATTEMPT.name());

            AUDIT.info("Registration attempt for user: {}", req.getUsername());
        } finally {
            clearMdc();
        }
    }

    @AfterReturning("register()")
    public void registerSuccess(JoinPoint jp) {
        RegisterRequest req = extractArg(jp, RegisterRequest.class, 0);
        String ip = extractArg(jp, String.class, 2);

        if (req == null) return;

        try {
            putBaseContext(req.getUsername(), ip);
            MDC.put(MdcKeysConstants.EVENT_TYPE, EventType.AUTH.name());
            MDC.put(MdcKeysConstants.EVENT_ACTION, EventAction.REGISTER_SUCCESS.name());

            AUDIT.info("Registration successful for user: {}", req.getUsername());
        } finally {
            clearMdc();
        }
    }

    @Before("refreshToken()")
    public void refreshAttempt(JoinPoint jp) {
        String refreshToken = extractArg(jp, String.class, 0);
        String ip = extractArg(jp, String.class, 2);

        if (!StringUtils.hasText(refreshToken)) return;

        try {
            String user = extractUsernameFromToken(refreshToken);
            putBaseContext(user, ip);

            MDC.put(MdcKeysConstants.EVENT_TYPE, EventType.TOKEN.name());
            MDC.put(MdcKeysConstants.EVENT_ACTION, EventAction.REFRESH_TOKEN_ATTEMPT.name());

            AUDIT.info("Refresh token attempt for user: {}", user);
        } catch (Exception e) {
            log.debug("Could not extract username from token during refresh attempt", e);
        } finally {
            clearMdc();
        }
    }

    @AfterReturning("refreshToken()")
    public void refreshSuccess(JoinPoint jp) {
        String refreshToken = extractArg(jp, String.class, 0);
        String ip = extractArg(jp, String.class, 2);

        if (!StringUtils.hasText(refreshToken)) return;

        try {
            String user = extractUsernameFromToken(refreshToken);
            putBaseContext(user, ip);

            MDC.put(MdcKeysConstants.EVENT_TYPE, EventType.TOKEN.name());
            MDC.put(MdcKeysConstants.EVENT_ACTION, EventAction.REFRESH_TOKEN_SUCCESS.name());

            AUDIT.info("Refresh token successful for user: {}", user);
        } catch (Exception e) {
            log.debug("Could not extract username from token during refresh success", e);
        } finally {
            clearMdc();
        }
    }

    @AfterReturning("logout()")
    public void logoutSuccess(JoinPoint jp) {
        String refreshToken = extractArg(jp, String.class, 0);

        if (!StringUtils.hasText(refreshToken)) return;

        try {
            String user = extractUsernameFromToken(refreshToken);
            putBaseContext(user, null);

            MDC.put(MdcKeysConstants.EVENT_TYPE, EventType.AUTH.name());
            MDC.put(MdcKeysConstants.EVENT_ACTION, EventAction.LOGOUT.name());

            AUDIT.info("Logout successful for user: {}", user);
        } catch (Exception e) {
            log.debug("Could not extract username from token during logout", e);
        } finally {
            clearMdc();
        }
    }

    private void putBaseContext(String user, String ip) {
        if (user != null) MDC.put(MdcKeysConstants.USER, user);
        if (ip != null) MDC.put(MdcKeysConstants.IP, ip);
    }

    @SuppressWarnings("unchecked")
    private <T> T extractArg(JoinPoint jp, Class<T> type, int index) {
        Object[] args = jp.getArgs();
        if (args != null && args.length > index && type.isInstance(args[index])) {
            return (T) args[index];
        }
        return null;
    }

    private String extractUsernameFromToken(String token) {
        try {
            return jwtProvider.extractUsername(token);
        } catch (Exception e) {
            log.debug("Failed to extract username from token", e);
            return "UNKNOWN";
        }
    }

    private void clearMdc() {
        MDC.remove(MdcKeysConstants.USER);
        MDC.remove(MdcKeysConstants.IP);
        MDC.remove(MdcKeysConstants.EVENT_TYPE);
        MDC.remove(MdcKeysConstants.EVENT_ACTION);
    }
}