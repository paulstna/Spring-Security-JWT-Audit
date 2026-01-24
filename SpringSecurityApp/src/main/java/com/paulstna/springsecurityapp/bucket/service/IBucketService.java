package com.paulstna.springsecurityapp.bucket.service;

import io.github.bucket4j.Bucket;

public interface IBucketService {
    Bucket createBucket(String metricsKey);

    boolean isRateLimited(String endpoint);
}
