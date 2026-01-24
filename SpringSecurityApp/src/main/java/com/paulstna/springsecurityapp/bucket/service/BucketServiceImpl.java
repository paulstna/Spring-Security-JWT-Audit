package com.paulstna.springsecurityapp.bucket.service;

import com.paulstna.springsecurityapp.bucket.config.BucketLimitationConfiguration;
import com.paulstna.springsecurityapp.bucket.domain.BucketMetrics;
import io.github.bucket4j.Bucket;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class BucketServiceImpl implements IBucketService {

    private final BucketLimitationConfiguration bucketLimitationConfiguration;

    @Override
    public Bucket createBucket(String metricsKey) {
        BucketMetrics bucketMetrics = resolveMetrics(metricsKey);

        return Bucket.builder()
                .addLimit(limit -> limit
                        .capacity(bucketMetrics.capacity())
                        .refillGreedy(
                                bucketMetrics.refillTokens(),
                                Duration.ofSeconds(bucketMetrics.refillTime())))
                .build();
    }

    @Override
    public boolean isRateLimited(String endpoint) {
        return bucketLimitationConfiguration.getLimitedEndpoints().contains(endpoint);
    }

    private BucketMetrics resolveMetrics(String endpoint) {
        return Optional.ofNullable(
                bucketLimitationConfiguration.getBucketMetrics().get(endpoint)
        ).orElseThrow(() ->
                new IllegalStateException(
                        "No BucketMetrics configured for endpoint: " + endpoint
                )
        );
    }
}
