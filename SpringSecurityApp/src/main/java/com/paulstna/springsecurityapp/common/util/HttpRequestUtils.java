package com.paulstna.springsecurityapp.common.util;

import jakarta.servlet.http.HttpServletRequest;
import lombok.experimental.UtilityClass;
import org.springframework.util.StringUtils;

@UtilityClass
public class HttpRequestUtils {
    public String extractEndpoint(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (!StringUtils.hasText(path)) {
            return "unknown";
        }

        String normalized = path.endsWith("/")
                ? path.substring(0, path.length() - 1)
                : path;

        return normalized.substring(normalized.lastIndexOf('/') + 1);
    }
}
