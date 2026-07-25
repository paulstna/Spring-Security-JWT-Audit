package com.paulstna.springsecurityapp.audit.aspect;

import com.paulstna.springsecurityapp.audit.constants.MdcKeysConstants;
import com.paulstna.springsecurityapp.audit.enums.EventOutcome;
import com.paulstna.springsecurityapp.audit.enums.EventType;
import com.paulstna.springsecurityapp.audit.enums.FailureReason;
import com.paulstna.springsecurityapp.audit.enums.Severity;
import com.paulstna.springsecurityapp.exception.*;
import io.jsonwebtoken.JwtException;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.dao.DataAccessException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class ErrorLoggingAspect {

    private static final Logger ERROR_LOGGER = LoggerFactory.getLogger("ERROR");


    @AfterThrowing(
            pointcut = "execution(* com.paulstna.springsecurityapp.auth.service.AuthServiceImpl.*(..))",
            throwing = "ex"
    )
    public void logAuthServiceErrors(JoinPoint jp, Throwable ex) {
        if (isExpectedBusinessException(ex)) {
            return;
        }

        String className  = jp.getSignature().getDeclaringTypeName();
        String methodName = jp.getSignature().getName();

        try {
            MDC.put(MdcKeysConstants.EVENT_TYPE, EventType.SYSTEM.name());
            MDC.put(MdcKeysConstants.EVENT_ACTION, methodName.toUpperCase());
            MDC.put(MdcKeysConstants.EVENT_OUTCOME, EventOutcome.ERROR.name());
            MDC.put(MdcKeysConstants.CLASS, className);
            MDC.put(MdcKeysConstants.METHOD, methodName);
            MDC.put(MdcKeysConstants.ERROR_TYPE, ex.getClass().getSimpleName());

            if (ex instanceof IllegalArgumentException || ex instanceof IllegalStateException) {
                MDC.put(MdcKeysConstants.FAILURE_REASON, FailureReason.INVALID_STATE.name());
                MDC.put(MdcKeysConstants.SEVERITY, Severity.MEDIUM.name());
                ERROR_LOGGER.error("INVALID_STATE in {}.{}: {}",
                        className, methodName, ex.getMessage(), ex);
            } else if (ex instanceof DataAccessException) {
                MDC.put(MdcKeysConstants.FAILURE_REASON, FailureReason.SYSTEM_ERROR.name());
                MDC.put(MdcKeysConstants.SEVERITY, Severity.HIGH.name());
                ERROR_LOGGER.error("DATABASE_ERROR in {}.{}: {}",
                        className, methodName, ex.getMessage(), ex);
            } else {
                MDC.put(MdcKeysConstants.FAILURE_REASON, FailureReason.UNEXPECTED_ERROR.name());
                MDC.put(MdcKeysConstants.SEVERITY, Severity.HIGH.name());
                ERROR_LOGGER.error("UNEXPECTED_ERROR {} in {}.{}: {}",
                        ex.getClass().getSimpleName(), className, methodName, ex.getMessage(), ex);
            }
        } finally {
            clearMDC();
        }
    }


    @AfterThrowing(
            pointcut = "execution(* com.paulstna.springsecurityapp.jwt.service..*(..))",
            throwing = "ex"
    )
    public void logJwtServiceErrors(JoinPoint jp, Throwable ex) {
        if (isExpectedBusinessException(ex)) {
            return;
        }

        String className  = jp.getSignature().getDeclaringTypeName();
        String methodName = jp.getSignature().getName();

        try {
            MDC.put(MdcKeysConstants.EVENT_TYPE, EventType.TOKEN.name());
            MDC.put(MdcKeysConstants.EVENT_ACTION, methodName.toUpperCase());
            MDC.put(MdcKeysConstants.EVENT_OUTCOME, EventOutcome.ERROR.name());
            MDC.put(MdcKeysConstants.CLASS, className);
            MDC.put(MdcKeysConstants.METHOD, methodName);
            MDC.put(MdcKeysConstants.ERROR_TYPE, ex.getClass().getSimpleName());
            MDC.put(MdcKeysConstants.FAILURE_REASON, FailureReason.SYSTEM_ERROR.name());
            MDC.put(MdcKeysConstants.SEVERITY, Severity.HIGH.name());

            ERROR_LOGGER.error("JWT_SERVICE_ERROR in {}.{}: {}",
                    className, methodName, ex.getMessage(), ex);
        } finally {
            clearMDC();
        }
    }

    @AfterThrowing(
            pointcut = "execution(* com.paulstna.springsecurityapp.user.service..*(..))",
            throwing = "ex"
    )
    public void logUserServiceErrors(JoinPoint jp, Throwable ex) {
        if (isExpectedBusinessException(ex)) {
            return;
        }

        String className  = jp.getSignature().getDeclaringTypeName();
        String methodName = jp.getSignature().getName();

        try {
            MDC.put(MdcKeysConstants.EVENT_TYPE, EventType.SYSTEM.name());
            MDC.put(MdcKeysConstants.EVENT_ACTION, methodName.toUpperCase());
            MDC.put(MdcKeysConstants.EVENT_OUTCOME, EventOutcome.ERROR.name());
            MDC.put(MdcKeysConstants.CLASS, className);
            MDC.put(MdcKeysConstants.METHOD, methodName);
            MDC.put(MdcKeysConstants.ERROR_TYPE, ex.getClass().getSimpleName());

            if (ex instanceof DataAccessException) {
                MDC.put(MdcKeysConstants.FAILURE_REASON, FailureReason.SYSTEM_ERROR.name());
                MDC.put(MdcKeysConstants.SEVERITY, Severity.HIGH.name());
                ERROR_LOGGER.error("DATABASE_ERROR in {}.{}: {}",
                        className, methodName, ex.getMessage(), ex);
            } else {
                MDC.put(MdcKeysConstants.FAILURE_REASON, FailureReason.UNEXPECTED_ERROR.name());
                MDC.put(MdcKeysConstants.SEVERITY, Severity.MEDIUM.name());
                ERROR_LOGGER.error("USER_SERVICE_ERROR in {}.{}: {}",
                        className, methodName, ex.getMessage(), ex);
            }
        } finally {
            clearMDC();
        }
    }

    /**
     * Business exceptions should NOT be logged as system errors.
     */
    private boolean isExpectedBusinessException(Throwable ex) {
        return ex instanceof AccessDeniedException ||
                ex instanceof BadCredentialsException ||
                ex instanceof InvalidTokenException ||
                ex instanceof TokenRequiredException ||
                ex instanceof ResourceNotFoundException ||
                ex instanceof ResourceAlreadyExistsException ||
                ex instanceof LockedException ||
                ex instanceof DisabledException ||
                // Malformed, expired or badly signed tokens are the client's
                // doing, not a fault of this service.
                ex instanceof JwtException;
    }

    private void clearMDC() {
        MDC.remove(MdcKeysConstants.EVENT_TYPE);
        MDC.remove(MdcKeysConstants.EVENT_ACTION);
        MDC.remove(MdcKeysConstants.EVENT_OUTCOME);
        MDC.remove(MdcKeysConstants.FAILURE_REASON);
        MDC.remove(MdcKeysConstants.CLASS);
        MDC.remove(MdcKeysConstants.METHOD);
        MDC.remove(MdcKeysConstants.ERROR_TYPE);
        MDC.remove(MdcKeysConstants.SEVERITY);
    }
}