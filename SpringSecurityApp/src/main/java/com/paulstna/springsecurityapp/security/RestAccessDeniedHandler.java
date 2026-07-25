package com.paulstna.springsecurityapp.security;

import com.paulstna.springsecurityapp.exception.ErrorResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Answers callers who are authenticated but lack the role.
 * <p>
 * Retrying will not help them, which is exactly what {@code 403} means and what
 * {@link RestAuthenticationEntryPoint} exists to distinguish this from.
 */
@Component
@RequiredArgsConstructor
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    private final ErrorResponseWriter errorResponseWriter;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        errorResponseWriter.write(request, response, HttpStatus.FORBIDDEN,
                "Access denied");
    }
}
