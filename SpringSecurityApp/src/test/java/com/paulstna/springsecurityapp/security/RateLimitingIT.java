package com.paulstna.springsecurityapp.security;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.paulstna.springsecurityapp.support.AbstractIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Transactional
@DisplayName("Rate limiting")
class RateLimitingIT extends AbstractIntegrationTest {

    private static final int LOGIN_CAPACITY = 5;
    private static final int REGISTER_CAPACITY = 3;

    @Test
    @DisplayName("login allows a burst up to capacity and then answers 429")
    void loginBucketIsEnforced() throws Exception {
        for (int attempt = 1; attempt <= LOGIN_CAPACITY; attempt++) {
            assertThat(attemptLogin(null).getStatus())
                    .as("attempt %d is within capacity", attempt)
                    .isEqualTo(401);
        }

        assertThat(attemptLogin(null).getStatus())
                .as("the request past capacity must be rate limited")
                .isEqualTo(429);
    }

    @Test
    @DisplayName("a rate limited response carries Retry-After and the standard error body")
    void rateLimitedResponseIsInformative() throws Exception {
        for (int attempt = 0; attempt < LOGIN_CAPACITY; attempt++) {
            attemptLogin(null);
        }

        MockHttpServletResponse limited = attemptLogin(null);

        assertThat(limited.getStatus()).isEqualTo(429);
        assertThat(limited.getHeader(HttpHeaders.RETRY_AFTER))
                .as("clients need to know how long to wait")
                .isNotNull();
        assertThat(limited.getHeader("X-RateLimit-Remaining")).isEqualTo("0");

        // The limiter is a filter, so this body used to have a shape of its own
        // and a client had to parse two kinds of error.
        assertThat(limited.getContentType()).contains(MediaType.APPLICATION_JSON_VALUE);
        assertThat(limited.getContentAsString())
                .contains("\"status\":429")
                .contains("Rate limit exceeded")
                .contains("\"path\":\"/api/v1/auth/login\"")
                .as("the limiter used to run before the MDC filter, so the one response "
                        + "a caller most wants to correlate had no id to quote")
                .contains("\"traceId\"");
    }

    /**
     * An exhausted bucket is the clearest signal this service gets that someone
     * is guessing credentials. It used to leave no trace at all.
     */
    @Test
    @DisplayName("hitting the limit is recorded as a security event")
    void rateLimitingIsAudited() throws Exception {
        ListAppender<ILoggingEvent> securityLog = new ListAppender<>();
        securityLog.start();
        Logger logger = (Logger) LoggerFactory.getLogger("SECURITY");
        logger.addAppender(securityLog);

        try {
            for (int attempt = 0; attempt <= LOGIN_CAPACITY; attempt++) {
                attemptLogin(null);
            }

            assertThat(securityLog.list).anySatisfy(event -> {
                assertThat(event.getFormattedMessage()).contains("Rate limit exceeded");
                assertThat(event.getMDCPropertyMap())
                        .containsEntry("eventAction", "RATE_LIMIT_EXCEEDED")
                        .containsEntry("failureReason", "RATE_LIMIT_EXCEEDED")
                        .containsEntry("eventType", "SECURITY");
                assertThat(event.getMDCPropertyMap().get("traceId")).isNotBlank();
                assertThat(event.getMDCPropertyMap().get("ip")).isNotBlank();
            });
        } finally {
            logger.detachAppender(securityLog);
        }
    }

    /**
     * Regression: X-Forwarded-For was trusted unconditionally, so rotating the
     * header on every request gave each one its own bucket and walked straight
     * past the limiter. It is only honoured when app.trust-proxy is enabled.
     */
    @Test
    @DisplayName("rotating X-Forwarded-For does not buy extra attempts")
    void spoofedForwardedForDoesNotBypassTheLimiter() throws Exception {
        for (int attempt = 1; attempt <= LOGIN_CAPACITY; attempt++) {
            assertThat(attemptLogin("203.0.113." + attempt).getStatus()).isEqualTo(401);
        }

        assertThat(attemptLogin("203.0.113.99").getStatus())
                .as("a fresh spoofed IP must not reset the bucket")
                .isEqualTo(429);
    }

    @Test
    @DisplayName("register has its own, stricter bucket")
    void registerBucketIsEnforcedIndependently() throws Exception {
        for (int attempt = 1; attempt <= REGISTER_CAPACITY; attempt++) {
            assertThat(attemptRegister("burst" + attempt).getStatus()).isEqualTo(201);
        }

        assertThat(attemptRegister("burst-too-many").getStatus()).isEqualTo(429);
    }

    @Test
    @DisplayName("exhausting one endpoint's bucket leaves the others usable")
    void bucketsAreScopedPerEndpoint() throws Exception {
        for (int attempt = 0; attempt <= REGISTER_CAPACITY; attempt++) {
            attemptRegister("scoped" + attempt);
        }
        assertThat(attemptRegister("scoped-final").getStatus()).isEqualTo(429);

        assertThat(attemptLogin(null).getStatus())
                .as("login must not be affected by the register bucket")
                .isEqualTo(401);
    }

    @Test
    @DisplayName("endpoints outside the limited list are never throttled")
    void unlimitedEndpointsAreNotThrottled() throws Exception {
        String token = accessTokenFor(MANAGER);

        for (int request = 0; request < 20; request++) {
            mockMvc.perform(get("/api/v1/users").header(HttpHeaders.AUTHORIZATION, bearer(token)))
                    .andExpect(status().isOk());
        }
    }

    private MockHttpServletResponse attemptLogin(String forwardedFor) throws Exception {
        var request = post("/api/v1/auth/login")
                .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                .contentType(MediaType.APPLICATION_JSON)
                .content(credentials("nobody", "Wrong1234!"));

        if (forwardedFor != null) {
            request = request.header("X-Forwarded-For", forwardedFor);
        }
        return mockMvc.perform(request).andReturn().getResponse();
    }

    private MockHttpServletResponse attemptRegister(String username) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/register")
                        .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credentials(username, "Valid1234!")))
                .andReturn()
                .getResponse();
    }
}
