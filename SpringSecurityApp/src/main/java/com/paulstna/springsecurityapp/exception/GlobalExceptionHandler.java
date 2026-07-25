package com.paulstna.springsecurityapp.exception;

import com.paulstna.springsecurityapp.audit.constants.MdcKeysConstants;
import com.paulstna.springsecurityapp.exception.dto.ErrorResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponseDTO> handleResourceNotFound(
            ResourceNotFoundException e, HttpServletRequest request) {
        return respond(HttpStatus.NOT_FOUND, e.getMessage(), request.getRequestURI());
    }

    @ExceptionHandler(ResourceAlreadyExistsException.class)
    public ResponseEntity<ErrorResponseDTO> handleResourceAlreadyExists(
            ResourceAlreadyExistsException e, HttpServletRequest request) {
        return respond(HttpStatus.CONFLICT, e.getMessage(), request.getRequestURI());
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ErrorResponseDTO> handleInvalidToken(
            InvalidTokenException e, HttpServletRequest request) {
        return respond(HttpStatus.UNAUTHORIZED, e.getMessage(), request.getRequestURI());
    }

    @ExceptionHandler(TokenRequiredException.class)
    public ResponseEntity<ErrorResponseDTO> handleTokenRequired(
            TokenRequiredException e, HttpServletRequest request) {
        return respond(HttpStatus.BAD_REQUEST, e.getMessage(), request.getRequestURI());
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponseDTO> handleAccessDenied(
            AccessDeniedException e, HttpServletRequest request) {
        return respond(HttpStatus.FORBIDDEN, e.getMessage(), request.getRequestURI());
    }

    @ExceptionHandler({BadCredentialsException.class, AccountStatusException.class})
    public ResponseEntity<ErrorResponseDTO> handleFailedAuthentication(
            AuthenticationException e, HttpServletRequest request) {
        return respond(HttpStatus.UNAUTHORIZED, "Bad credentials", request.getRequestURI());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponseDTO> handleUnexpected(
            Exception e, HttpServletRequest request) {
        log.error("Unhandled exception on {} {}", request.getMethod(), request.getRequestURI(), e);
        return respond(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error", request.getRequestURI());
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex, HttpHeaders headers,
            HttpStatusCode status, WebRequest request) {

        Map<String, String> fieldErrors = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
                // A field can break several rules at once; keep them all.
                fieldErrors.merge(error.getField(), error.getDefaultMessage(),
                        (existing, added) -> existing + "; " + added));

        return ResponseEntity.status(status).body(
                body(status, "Validation failed", pathOf(request), fieldErrors));
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(
            Exception ex, Object responseBody, HttpHeaders headers,
            HttpStatusCode status, WebRequest request) {

        Object payload = responseBody instanceof ErrorResponseDTO
                ? responseBody
                : body(status, reasonPhrase(status), pathOf(request), null);

        return super.handleExceptionInternal(ex, payload, headers, status, request);
    }

    private ResponseEntity<ErrorResponseDTO> respond(HttpStatus status, String message, String path) {
        return ResponseEntity.status(status).body(body(status, message, path, null));
    }

    private ErrorResponseDTO body(HttpStatusCode status, String message, String path,
                                  Map<String, String> fieldErrors) {
        return ErrorResponseDTO.builder()
                .timestamp(Instant.now())
                .status(status.value())
                .message(message)
                .path(path)
                .traceId(MDC.get(MdcKeysConstants.TRACE_ID))
                .fieldErrors(fieldErrors)
                .build();
    }

    private String pathOf(WebRequest request) {
        return request instanceof ServletWebRequest servletRequest
                ? servletRequest.getRequest().getRequestURI()
                : null;
    }

    private String reasonPhrase(HttpStatusCode status) {
        HttpStatus resolved = HttpStatus.resolve(status.value());
        return resolved != null ? resolved.getReasonPhrase() : "Request failed";
    }
}
