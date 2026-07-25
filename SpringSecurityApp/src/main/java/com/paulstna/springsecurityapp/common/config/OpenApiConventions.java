package com.paulstna.springsecurityapp.common.config;

import com.paulstna.springsecurityapp.bucket.config.BucketLimitationConfiguration;
import com.paulstna.springsecurityapp.exception.dto.ErrorResponseDTO;
import io.swagger.v3.core.converter.ModelConverters;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.Paths;
import io.swagger.v3.oas.models.headers.Header;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import lombok.RequiredArgsConstructor;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;

import java.util.Set;

/**
 * Rules that apply to the whole document, kept out of the controllers.
 * <p>
 * The responses added here are produced by filters and the exception handler,
 * not by controller code, so documenting them centrally mirrors where they
 * actually come from and keeps every operation consistent.
 */
@Configuration
@RequiredArgsConstructor
public class OpenApiConventions {

    private static final String ERROR_SCHEMA_REF =
            "#/components/schemas/" + ErrorResponseDTO.SCHEMA_NAME;

    /** Spelled out because the swagger MediaType type is already imported here. */
    private static final String JSON = org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

    private final BucketLimitationConfiguration bucketLimitation;

    /**
     * Springdoc reads the path template literally, so every path comes out as
     * {@code /api/{version}/...}: it does not know about the {@code version}
     * attribute Spring 7 mappings use. Left alone, "Try it out" would call a URL
     * with a literal {@code {version}} in it.
     */
    @Bean
    public OpenApiCustomizer resolveVersionInPaths() {
        return openApi -> {
            Paths resolved = new Paths();
            resolved.extensions(openApi.getPaths().getExtensions());
            openApi.getPaths().forEach((path, item) -> resolved.addPathItem(
                    path.replace("{version}", ApiVersioningConfig.CURRENT_VERSION), item));
            openApi.setPaths(resolved);
        };
    }

    /**
     * Failures every endpoint shares. {@code 429} is added only where the rate
     * limiter is actually configured, read from the same properties the filter
     * uses, so the two cannot drift apart.
     */
    @Bean
    public OpenApiCustomizer documentCommonFailures() {
        return openApi -> {
            ModelConverters.getInstance()
                    .read(ErrorResponseDTO.class)
                    .forEach(openApi.getComponents()::addSchemas);

            Set<String> rateLimited = bucketLimitation.getLimitedEndpoints();

            openApi.getPaths().forEach((path, item) -> {
                boolean limited = rateLimited.contains(lastSegment(path));
                item.readOperations().forEach(operation -> {
                    if (limited) {
                        addTooManyRequests(operation);
                    }
                    addServerError(operation);
                });
            });
        };
    }

    private void addTooManyRequests(Operation operation) {
        ApiResponse response = errorResponse(
                "Rate limit exceeded for this client IP. Wait the number of seconds "
                        + "in the Retry-After header.");
        response.addHeaderObject(HttpHeaders.RETRY_AFTER, new Header()
                .description("Seconds until the next attempt is allowed.")
                .schema(new Schema<>().type("integer")));

        responses(operation).addApiResponse("429", response);
    }

    private void addServerError(Operation operation) {
        responses(operation).addApiResponse("500", errorResponse(
                "Unexpected failure. The body carries a traceId that matches the log entry; "
                        + "no internal detail is exposed."));
    }

    private ApiResponse errorResponse(String description) {
        return new ApiResponse()
                .description(description)
                .content(new Content().addMediaType(
                        JSON, new MediaType().schema(new Schema<>().$ref(ERROR_SCHEMA_REF))));
    }

    private ApiResponses responses(Operation operation) {
        if (operation.getResponses() == null) {
            operation.setResponses(new ApiResponses());
        }
        return operation.getResponses();
    }

    /** {@code /api/v1/auth/login} to {@code login}, matching how buckets are keyed. */
    private String lastSegment(String path) {
        return path.substring(path.lastIndexOf('/') + 1);
    }
}
