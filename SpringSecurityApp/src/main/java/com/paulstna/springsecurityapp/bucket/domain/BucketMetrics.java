package com.paulstna.springsecurityapp.bucket.domain;

public record BucketMetrics(
        Integer capacity,
        Integer refillTokens,
        Long refillTime
) {
}
