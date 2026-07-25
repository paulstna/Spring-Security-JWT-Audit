package com.paulstna.springsecurityapp.support;

import com.github.benmanes.caffeine.cache.Cache;
import com.jayway.jsonpath.JsonPath;
import io.github.bucket4j.Bucket;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Base for integration tests.
 * <p>
 * Runs against a real PostgreSQL container rather than an in-memory database, so
 * the Flyway migrations, the {@code ddl-auto=validate} check and Postgres-specific
 * SQL are exercised exactly as they are in production.
 * <p>
 * The container is started once on first class load and shared by every test
 * class; Spring's context cache then reuses a single application context.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public abstract class AbstractIntegrationTest {

    /** Same image as compose.yaml, so tests run on the production PostgreSQL version. */
    private static final PostgreSQLContainer POSTGRES =
            new PostgreSQLContainer("postgres:17-alpine");

    static {
        POSTGRES.start();
    }

    /** Password of the demo accounts seeded by V3__seed_users.sql. */
    protected static final String DEMO_PASSWORD = "Demo1234!";

    protected static final String ADMIN = "admin";
    protected static final String MANAGER = "manager";
    protected static final String USER = "user";

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    private Cache<String, Bucket> bucketCache;

    @DynamicPropertySource
    static void datasourceProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    /**
     * Rate limiter buckets live in a shared Caffeine cache. Without clearing them
     * a test that exhausts a bucket would make later tests fail for the wrong reason.
     */
    @BeforeEach
    void resetRateLimiterBuckets() {
        bucketCache.invalidateAll();
    }

    /**
     * Refresh tokens are bound to the User-Agent that requested them, and the
     * column is NOT NULL, so every test request must carry one.
     */
    protected static final String TEST_USER_AGENT = "integration-test-agent/1.0";

    protected MockHttpServletResponse loginResponse(String username, String password) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/login")
                        .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credentials(username, password)))
                .andReturn()
                .getResponse();
    }

    protected String accessTokenFor(String username) throws Exception {
        return readString(loginResponse(username, DEMO_PASSWORD).getContentAsString(), "$.authToken");
    }

    protected String refreshTokenFor(String username) throws Exception {
        return refreshCookieValue(loginResponse(username, DEMO_PASSWORD));
    }

    protected String refreshCookieValue(MockHttpServletResponse response) {
        Cookie cookie = response.getCookie("refreshToken");
        return cookie != null ? cookie.getValue() : null;
    }

    protected String credentials(String username, String password) {
        return """
                {"username":"%s","password":"%s"}""".formatted(username, password);
    }

    protected String bearer(String token) {
        return "Bearer " + token;
    }

    protected String readString(String json, String path) {
        return JsonPath.read(json, path);
    }
}
