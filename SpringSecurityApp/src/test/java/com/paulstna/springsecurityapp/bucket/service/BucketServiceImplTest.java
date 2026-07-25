package com.paulstna.springsecurityapp.bucket.service;

import com.paulstna.springsecurityapp.bucket.config.BucketLimitationConfiguration;
import com.paulstna.springsecurityapp.bucket.domain.BucketMetrics;
import io.github.bucket4j.Bucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("BucketServiceImpl")
class BucketServiceImplTest {

    private BucketServiceImpl service;

    @BeforeEach
    void setUp() {
        BucketLimitationConfiguration configuration = new BucketLimitationConfiguration();
        configuration.setLimitedEndpoints(Set.of("login", "register"));
        configuration.setBucketMetrics(Map.of(
                "login", new BucketMetrics(5, 2, 60L),
                "register", new BucketMetrics(3, 3, 600L)));

        service = new BucketServiceImpl(configuration);
    }

    @Test
    @DisplayName("only the configured endpoints are limited")
    void recognisesLimitedEndpoints() {
        assertThat(service.isRateLimited("login")).isTrue();
        assertThat(service.isRateLimited("register")).isTrue();
        assertThat(service.isRateLimited("users")).isFalse();
        assertThat(service.isRateLimited("unknown")).isFalse();
    }

    @Test
    @DisplayName("a bucket allows exactly its configured capacity before refusing")
    void capacityIsHonoured() {
        Bucket bucket = service.createBucket("login");

        for (int attempt = 1; attempt <= 5; attempt++) {
            assertThat(bucket.tryConsume(1)).as("attempt %d", attempt).isTrue();
        }
        assertThat(bucket.tryConsume(1)).as("the sixth attempt exceeds the capacity of 5").isFalse();
    }

    @Test
    @DisplayName("each endpoint gets its own capacity")
    void capacityIsPerEndpoint() {
        Bucket register = service.createBucket("register");

        for (int attempt = 1; attempt <= 3; attempt++) {
            assertThat(register.tryConsume(1)).isTrue();
        }
        assertThat(register.tryConsume(1)).isFalse();
    }

    @Test
    @DisplayName("separate buckets do not share tokens")
    void bucketsAreIndependent() {
        Bucket first = service.createBucket("login");
        Bucket second = service.createBucket("login");

        first.tryConsume(5);

        assertThat(first.tryConsume(1)).isFalse();
        assertThat(second.tryConsume(1))
                .as("a bucket for a different client must be unaffected")
                .isTrue();
    }

    @Test
    @DisplayName("a limited endpoint with no metrics fails loudly instead of running unlimited")
    void missingMetricsIsAnError() {
        assertThatThrownBy(() -> service.createBucket("refresh"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No BucketMetrics configured");
    }
}
