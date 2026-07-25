package com.paulstna.springsecurityapp.exception;

import com.paulstna.springsecurityapp.audit.constants.MdcKeysConstants;
import com.paulstna.springsecurityapp.exception.dto.ErrorResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * Writes the standard error body from outside the DispatcherServlet.
 * <p>
 * {@link GlobalExceptionHandler} only sees what reaches a controller, so
 * anything the security filter chain rejects never passes through it. Without
 * this, those responses came back with an empty body or a shape of their own,
 * and a client had to special case them.
 * <p>
 * It serialises with the application's own {@code JsonMapper}, the one Spring
 * MVC uses, so a failure from a filter is indistinguishable from one raised in
 * a controller.
 */
@Component
@RequiredArgsConstructor
public class ErrorResponseWriter {

    private final JsonMapper jsonMapper;

    public void write(HttpServletRequest request, HttpServletResponse response,
                      HttpStatus status, String message) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        jsonMapper.writeValue(response.getWriter(), ErrorResponseDTO.builder()
                .timestamp(Instant.now())
                .status(status.value())
                .message(message)
                .path(request.getRequestURI())
                .traceId(MDC.get(MdcKeysConstants.TRACE_ID))
                .build());
    }
}
