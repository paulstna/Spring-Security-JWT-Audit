package com.paulstna.springsecurityapp.bucket.config;

import com.paulstna.springsecurityapp.bucket.domain.BucketMetrics;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;
import java.util.Set;

@Setter
@Getter
@ConfigurationProperties( prefix = "bucket")
public class BucketLimitationConfiguration {
    private Set<String> limitedEndpoints;
    private Map<String, BucketMetrics> bucketMetrics;
}
