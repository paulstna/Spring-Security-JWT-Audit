package com.paulstna.springsecurityapp.audit.aspect;

import com.paulstna.springsecurityapp.audit.constants.MdcKeysConstants;
import com.paulstna.springsecurityapp.audit.enums.EventAction;
import com.paulstna.springsecurityapp.audit.enums.EventOutcome;
import com.paulstna.springsecurityapp.audit.enums.EventType;
import com.paulstna.springsecurityapp.audit.enums.FailureReason;
import com.paulstna.springsecurityapp.auth.domain.LoginRequest;
import com.paulstna.springsecurityapp.auth.domain.RegisterRequest;
import com.paulstna.springsecurityapp.exception.*;
import com.paulstna.springsecurityapp.jwt.service.IJwtProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.authentication.*;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class SecurityAuthAspect {

    private static final Logger SECURITY = LoggerFactory.getLogger("SECURITY");
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


    @AfterThrowing(pointcut = "login()", throwing = "ex")
    public void handleLoginFailure(JoinPoint jp, Throwable ex) {
        LoginRequest req = extractArg(jp, LoginRequest.class, 0);
        String ip = extractArg(jp, String.class, 2);

        logAuthFailure(
                req != null ? req.getUsername() : "UNKNOWN",
                ip,
                EventAction.LOGIN_FAILED,
                ex
        );
    }

    @AfterThrowing(pointcut = "register()", throwing = "ex")
    public void handleRegisterFailure(JoinPoint jp, Throwable ex) {
        RegisterRequest req = extractArg(jp, RegisterRequest.class, 0);
        String ip = extractArg(jp, String.class, 2);

        logAuthFailure(
                req != null ? req.getUsername() : "UNKNOWN",
                ip,
                EventAction.REGISTER_FAILED,
                ex
        );
    }

    @AfterThrowing(pointcut = "refreshToken()", throwing = "ex")
    public void handleRefreshTokenFailure(JoinPoint jp, Throwable ex) {
        String refreshToken = extractArg(jp, String.class, 0);
        String ip = extractArg(jp, String.class, 2);

        String username = "UNKNOWN";
        if (StringUtils.hasText(refreshToken)) {
            try {
                username = jwtProvider.extractUsername(refreshToken);
            } catch (Exception e) {
                log.debug("Could not extract username from token", e);
            }
        }

        logTokenFailure(username, ip, EventAction.REFRESH_TOKEN_FAILED, ex);
    }


    private void logAuthFailure(String username, String ip, EventAction action, Throwable ex) {
        FailureReason reason = mapFailureReason(ex);

        if (reason == FailureReason.INVALID_STATE ||
                reason == FailureReason.UNEXPECTED_ERROR) {
            return;
        }

        try {
            putBaseContext(username, ip);
            MDC.put(MdcKeysConstants.EVENT_TYPE, EventType.AUTH.name());
            MDC.put(MdcKeysConstants.EVENT_ACTION, action.name());
            MDC.put(MdcKeysConstants.EVENT_OUTCOME, EventOutcome.FAILURE.name());
            MDC.put(MdcKeysConstants.FAILURE_REASON, reason.name());

            SECURITY.warn("Authentication failure - User: {}, Reason: {}",
                    username, reason.name());
        } finally {
            clearMdc();
        }
    }

    private void logTokenFailure(String username, String ip, EventAction action, Throwable ex) {
        FailureReason reason = mapFailureReason(ex);

        if (reason == FailureReason.INVALID_STATE ||
                reason == FailureReason.UNEXPECTED_ERROR) {
            log.debug("Invalid state in auth operation: {}", ex.getMessage());
            return;
        }

        try {
            putBaseContext(username, ip);
            MDC.put(MdcKeysConstants.EVENT_TYPE, EventType.TOKEN.name());
            MDC.put(MdcKeysConstants.EVENT_ACTION, action.name());
            MDC.put(MdcKeysConstants.EVENT_OUTCOME, EventOutcome.FAILURE.name());
            MDC.put(MdcKeysConstants.FAILURE_REASON, reason.name());

            SECURITY.warn("Token operation failure - User: {}, Reason: {}",
                    username, reason.name());
        } finally {
            clearMdc();
        }
    }

    private FailureReason mapFailureReason(Throwable ex) {
        if (ex instanceof BadCredentialsException) {
            return FailureReason.INVALID_CREDENTIALS;
        }
        if (ex instanceof LockedException) {
            return FailureReason.ACCOUNT_LOCKED;
        }
        if (ex instanceof DisabledException) {
            return FailureReason.ACCOUNT_DISABLED;
        }
        if (ex instanceof InvalidTokenException) {
            return FailureReason.INVALID_TOKEN;
        }
        if (ex instanceof TokenRequiredException) {
            return FailureReason.TOKEN_REQUIRED;
        }
        if (ex instanceof ResourceNotFoundException) {
            return FailureReason.USER_NOT_FOUND;
        }
        if (ex instanceof IllegalArgumentException || ex instanceof IllegalStateException) {
            return FailureReason.INVALID_STATE;
        }
        return FailureReason.UNEXPECTED_ERROR;
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

    private void clearMdc() {
        MDC.remove(MdcKeysConstants.USER);
        MDC.remove(MdcKeysConstants.IP);
        MDC.remove(MdcKeysConstants.EVENT_TYPE);
        MDC.remove(MdcKeysConstants.EVENT_ACTION);
        MDC.remove(MdcKeysConstants.EVENT_OUTCOME);
        MDC.remove(MdcKeysConstants.FAILURE_REASON);
    }
}