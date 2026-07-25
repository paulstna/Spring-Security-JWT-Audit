package com.paulstna.springsecurityapp.exception.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.Map;

/**
 * Single error shape for the whole API.
 * <p>
 * {@code traceId} mirrors the value the request was logged under, so a caller
 * can quote it and the exact request can be found in the logs.
 */
@Getter
@Setter
@Builder
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponseDto {
    private Instant timestamp;
    private Integer status;
    private String message;
    private String path;
    private String traceId;

    /** Field name to message, only present on validation failures. */
    private Map<String, String> fieldErrors;
}
