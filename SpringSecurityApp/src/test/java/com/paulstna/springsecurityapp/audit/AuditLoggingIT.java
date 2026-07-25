package com.paulstna.springsecurityapp.audit;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.paulstna.springsecurityapp.support.AbstractIntegrationTest;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Locks in how events are classified. The audit trail is the point of this
 * project, so "which log did it land in" is behaviour worth asserting.
 */
@Transactional
@DisplayName("Audit and security logging")
class AuditLoggingIT extends AbstractIntegrationTest {

    private ListAppender<ILoggingEvent> errorLog;
    private ListAppender<ILoggingEvent> securityLog;
    private ListAppender<ILoggingEvent> auditLog;

    @BeforeEach
    void attachAppenders() {
        errorLog = attachTo("ERROR");
        securityLog = attachTo("SECURITY");
        auditLog = attachTo("AUDIT");
    }

    @AfterEach
    void detachAppenders() {
        detachFrom("ERROR", errorLog);
        detachFrom("SECURITY", securityLog);
        detachFrom("AUDIT", auditLog);
    }

    private ListAppender<ILoggingEvent> attachTo(String loggerName) {
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        ((Logger) LoggerFactory.getLogger(loggerName)).addAppender(appender);
        return appender;
    }

    private void detachFrom(String loggerName, ListAppender<ILoggingEvent> appender) {
        ((Logger) LoggerFactory.getLogger(loggerName)).detachAppender(appender);
    }

    private List<ILoggingEvent> errors() {
        return errorLog.list.stream().filter(e -> e.getLevel() == Level.ERROR).toList();
    }

    /**
     * Regression: a duplicate username is a legitimate 409, but it used to be
     * logged twice at ERROR with severity HIGH, which is alert fatigue.
     */
    @Test
    @DisplayName("a duplicate username is not logged as a system error")
    void duplicateUsernameIsNotASystemError() throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"admin","password":"Valid1234!"}"""))
                .andExpect(status().isConflict());

        assertThat(errors())
                .as("a client sending a name that is already taken is not a fault of this service")
                .isEmpty();
    }

    @Test
    @DisplayName("a malformed token from a client is not logged as a system error")
    void malformedTokenIsNotASystemError() throws Exception {
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                        .cookie(new Cookie("refreshToken", "clearly.not.a.jwt")))
                .andExpect(status().isUnauthorized());

        assertThat(errors()).isEmpty();
    }

    /**
     * Regression: this landed in the error log as UNEXPECTED_ERROR and never
     * reached the security log at all, which is where it belongs.
     */
    @Test
    @DisplayName("a privilege escalation attempt is recorded as a security event")
    void escalationAttemptIsASecurityEvent() throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"climber","password":"Valid1234!","roles":["SYSTEM"]}"""))
                .andExpect(status().isForbidden());

        assertThat(securityLog.list)
                .as("the most security-relevant event on this endpoint must be in the security log")
                .anySatisfy(event -> {
                    assertThat(event.getLevel()).isEqualTo(Level.WARN);
                    assertThat(event.getFormattedMessage()).contains("Authorization denied");
                    assertThat(event.getMDCPropertyMap())
                            .containsEntry("eventAction", "AUTHORIZATION_DENIED")
                            .containsEntry("failureReason", "INSUFFICIENT_PRIVILEGES")
                            .containsEntry("eventType", "SECURITY");
                });

        assertThat(errors()).as("and not in the error log as an unexpected failure").isEmpty();
    }

    @Test
    @DisplayName("a failed login is recorded with its real reason")
    void failedLoginIsASecurityEvent() throws Exception {
        loginResponse(ADMIN, "Wrong1234!");

        assertThat(securityLog.list).anySatisfy(event -> {
            assertThat(event.getFormattedMessage()).contains("Authentication failure");
            assertThat(event.getMDCPropertyMap())
                    .containsEntry("eventAction", "LOGIN_FAILED")
                    .containsEntry("failureReason", "INVALID_CREDENTIALS");
        });
    }

    @Test
    @DisplayName("a locked account is logged with the real reason even though the response hides it")
    void lockedAccountReasonSurvivesInTheAuditTrail() throws Exception {
        mockMvc.perform(get("/api/v1/users")); // warm the context

        org.springframework.jdbc.core.JdbcTemplate jdbc =
                new org.springframework.jdbc.core.JdbcTemplate(dataSource);
        jdbc.update("UPDATE users SET account_non_locked = false WHERE username = ?", USER);

        loginResponse(USER, DEMO_PASSWORD);

        assertThat(securityLog.list).anySatisfy(event ->
                assertThat(event.getMDCPropertyMap()).containsEntry("failureReason", "ACCOUNT_LOCKED"));
    }

    @Test
    @DisplayName("successful authentication is recorded in the audit trail")
    void successfulLoginIsAudited() throws Exception {
        loginResponse(MANAGER, DEMO_PASSWORD);

        assertThat(auditLog.list).anySatisfy(event ->
                assertThat(event.getMDCPropertyMap()).containsEntry("eventAction", "LOGIN_ATTEMPT"));
        assertThat(auditLog.list).anySatisfy(event ->
                assertThat(event.getMDCPropertyMap()).containsEntry("eventAction", "LOGIN_SUCCESS"));
    }

    @Test
    @DisplayName("every logged request carries a trace id and the caller IP")
    void logsAreCorrelatable() throws Exception {
        loginResponse(ADMIN, "Wrong1234!");

        assertThat(securityLog.list).anySatisfy(event -> {
            assertThat(event.getMDCPropertyMap().get("traceId")).isNotBlank();
            assertThat(event.getMDCPropertyMap().get("ip")).isNotBlank();
        });
    }

    @org.springframework.beans.factory.annotation.Autowired
    private javax.sql.DataSource dataSource;
}
