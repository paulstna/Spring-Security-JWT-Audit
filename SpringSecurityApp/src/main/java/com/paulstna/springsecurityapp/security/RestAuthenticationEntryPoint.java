package com.paulstna.springsecurityapp.security;

import com.paulstna.springsecurityapp.exception.ErrorResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Answers callers who presented no usable credential.
 * <p>
 * Spring's stateless default answers {@code 403} to everyone, which tells a
 * client nothing: an expired access token and a missing role look identical,
 * although one is fixed by refreshing and the other never is. This separates
 * them, and {@link RestAccessDeniedHandler} keeps {@code 403} for its real
 * meaning.
 */
@Component
@RequiredArgsConstructor
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ErrorResponseWriter errorResponseWriter;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        // Deliberately vague: whether the token was absent, malformed, expired or
        // of the wrong type is in the security log, not in the reply.
        errorResponseWriter.write(request, response, HttpStatus.UNAUTHORIZED,
                "Authentication required");
    }
}
