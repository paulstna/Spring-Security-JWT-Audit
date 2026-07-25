package com.paulstna.springsecurityapp.common.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class ClientIpResolver {

    private static final String FORWARDED_FOR_HEADER = "X-Forwarded-For";

    @Value("${app.trust-proxy:false}")
    private boolean trustProxy;

    public String resolve(HttpServletRequest request) {
        if (trustProxy) {
            String forwardedFor = request.getHeader(FORWARDED_FOR_HEADER);
            if (StringUtils.hasText(forwardedFor)) {
                // Left-most entry is the original client; the rest are proxies.
                return forwardedFor.split(",")[0].trim();
            }
        }
        return request.getRemoteAddr();
    }
}
