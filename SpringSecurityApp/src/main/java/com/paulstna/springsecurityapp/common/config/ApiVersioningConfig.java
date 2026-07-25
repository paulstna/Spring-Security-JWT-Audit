package com.paulstna.springsecurityapp.common.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.accept.ApiVersionResolver;
import org.springframework.web.accept.PathApiVersionResolver;
import org.springframework.web.servlet.config.annotation.ApiVersionConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * API versioning, scoped to the API.
 * <p>
 * The version lives in the second path segment ({@code /api/v1/...}), which is
 * what {@code @GetMapping(version = "v1")} matches against.
 * <p>
 * The scoping matters. Version resolution runs for every request the main
 * handler mapping sees, so reading segment 1 unconditionally made anything
 * outside {@code /api/} fail with {@code 400}: it either found no second
 * segment ({@code /swagger-ui.html}) or found one that is not a version
 * ({@code /v3/api-docs}). Resolving no version at all for those paths, with
 * {@code versionRequired=false}, lets them through untouched.
 * <p>
 * Unknown versions are still rejected: {@code /api/v9/users} resolves {@code v9},
 * which no mapping declares, and gets a {@code 400}.
 */
@Configuration
public class ApiVersioningConfig implements WebMvcConfigurer {

    /** The only version this API serves. Every mapping declares it. */
    public static final String CURRENT_VERSION = "v1";

    private static final String API_PREFIX = "/api/";
    private static final int VERSION_SEGMENT = 1;

    private static final ApiVersionResolver PATH_SEGMENT_RESOLVER =
            new PathApiVersionResolver(VERSION_SEGMENT);

    @Override
    public void configureApiVersioning(ApiVersionConfigurer configurer) {
        configurer
                .useVersionResolver(ApiVersioningConfig::resolveApiVersion)
                .setVersionRequired(false);
    }

    private static String resolveApiVersion(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return path.startsWith(API_PREFIX) ? PATH_SEGMENT_RESOLVER.resolveVersion(request) : null;
    }
}
