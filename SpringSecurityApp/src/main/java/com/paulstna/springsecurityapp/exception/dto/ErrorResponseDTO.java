package com.paulstna.springsecurityapp.exception.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
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
@Schema(name = ErrorResponseDTO.SCHEMA_NAME, description = "Every failure in this API has this shape.")
public class ErrorResponseDTO {

    /** Name this shape gets in the OpenAPI document; the Dto suffix is an internal detail. */
    public static final String SCHEMA_NAME = "ErrorResponse";

    private Instant timestamp;

    @Schema(example = "400")
    private Integer status;

    @Schema(description = "Safe to show a user. Never carries a stack trace or internal detail.",
            example = "Validation failed")
    private String message;

    @Schema(example = "/api/v1/users")
    private String path;

    @Schema(description = "The id this request was logged under. Quote it and the exact request "
            + "can be found in the logs.",
            example = "b8f1c2d3-4e5a-6b7c-8d9e-0f1a2b3c4d5e")
    private String traceId;

    /** Field name to message, only present on validation failures. */
    @Schema(description = "Only present on a validation failure.",
            example = "{\"password\":\"Password must be between 8 and 72 characters\"}")
    private Map<String, String> fieldErrors;
}
