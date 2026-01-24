package com.paulstna.springsecurityapp.security.filter;

import com.github.benmanes.caffeine.cache.Cache;
import com.paulstna.springsecurityapp.bucket.service.IBucketService;
import com.paulstna.springsecurityapp.common.util.HttpRequestUtils;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class RateLimiterFilter extends OncePerRequestFilter {

    private final Cache<String, Bucket> bucketCache;

    private final IBucketService bucketService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String endpoint = HttpRequestUtils.extractEndpoint(request);
        if (!bucketService.isRateLimited(endpoint)) {
            filterChain.doFilter(request, response);
            return;
        }

        String key = endpoint + ":" + HttpRequestUtils.getClientIp(request);

        Bucket bucket = bucketCache.get(key,
                k -> bucketService.createBucket(endpoint));

        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

        if (probe.isConsumed()) {
            filterChain.doFilter(request, response);
        } else {
            sendRateLimitExceededResponse(response, probe);
        }
    }

    private void sendRateLimitExceededResponse(HttpServletResponse response,
                                               ConsumptionProbe probe)
            throws IOException {
        long waitTime = TimeUnit.NANOSECONDS.toSeconds(probe.getNanosToWaitForRefill());

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader("Retry-After", String.valueOf(waitTime));
        response.setHeader("X-RateLimit-Remaining", "0");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        response.getWriter().write(String.format("""
                {
                  "error": "TOO_MANY_REQUESTS",
                  "message": "Rate limit exceeded. Retry after %d seconds"
                }
                """, waitTime));
    }
}
