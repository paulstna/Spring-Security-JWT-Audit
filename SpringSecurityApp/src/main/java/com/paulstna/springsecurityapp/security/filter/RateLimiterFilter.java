package com.paulstna.springsecurityapp.security.filter;

import com.github.benmanes.caffeine.cache.Cache;
import com.paulstna.springsecurityapp.bucket.service.IBucketService;
import com.paulstna.springsecurityapp.common.util.HttpRequestUtils;
import com.paulstna.springsecurityapp.common.web.ClientIpResolver;
import com.paulstna.springsecurityapp.exception.ErrorResponseWriter;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class RateLimiterFilter extends OncePerRequestFilter {

    private final Cache<String, Bucket> bucketCache;

    private final IBucketService bucketService;

    private final ClientIpResolver clientIpResolver;

    private final ErrorResponseWriter errorResponseWriter;

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

        String key = endpoint + ":" + clientIpResolver.resolve(request);

        Bucket bucket = bucketCache.get(key,
                k -> bucketService.createBucket(endpoint));

        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

        if (probe.isConsumed()) {
            filterChain.doFilter(request, response);
        } else {
            sendRateLimitExceededResponse(request, response, probe);
        }
    }

    private void sendRateLimitExceededResponse(HttpServletRequest request,
                                               HttpServletResponse response,
                                               ConsumptionProbe probe)
            throws IOException {
        long waitTime = TimeUnit.NANOSECONDS.toSeconds(probe.getNanosToWaitForRefill());

        response.setHeader(HttpHeaders.RETRY_AFTER, String.valueOf(waitTime));
        response.setHeader("X-RateLimit-Remaining", "0");

        errorResponseWriter.write(request, response, HttpStatus.TOO_MANY_REQUESTS,
                "Rate limit exceeded. Retry after " + waitTime + " seconds");
    }
}
