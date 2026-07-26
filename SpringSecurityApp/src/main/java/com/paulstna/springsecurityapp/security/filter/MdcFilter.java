package com.paulstna.springsecurityapp.security.filter;

import com.paulstna.springsecurityapp.audit.constants.MdcKeysConstants;
import com.paulstna.springsecurityapp.common.web.ClientIpResolver;
import com.paulstna.springsecurityapp.security.SecurityUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class MdcFilter extends OncePerRequestFilter {

    private final ClientIpResolver clientIpResolver;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            MDC.put(MdcKeysConstants.TRACE_ID, UUID.randomUUID().toString());
            // Every request-scoped log line carries the caller IP, so security
            // events outside the auth flow are still attributable.
            MDC.put(MdcKeysConstants.IP, clientIpResolver.resolve(request));

            // The caller is not known yet: this filter runs before authentication so
            // that a request rejected by the rate limiter still gets a traceId.
            // JwtAuthenticationFilter adds the user once it has one.

            filterChain.doFilter(request, response);

        } finally {
            MDC.clear();
        }
    }
}
