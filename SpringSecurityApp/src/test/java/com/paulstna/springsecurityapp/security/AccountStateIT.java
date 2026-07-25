package com.paulstna.springsecurityapp.security;

import com.paulstna.springsecurityapp.support.AbstractIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Transactional
@DisplayName("Account state")
class AccountStateIT extends AbstractIntegrationTest {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @jakarta.persistence.PersistenceContext
    private jakarta.persistence.EntityManager entityManager;

    /**
     * Regression: enabled and accountNonLocked were hardcoded true on SecurityUser,
     * so the DisabledException and LockedException the audit aspect already mapped
     * could never actually be thrown.
     */
    @Test
    @DisplayName("disabling an account invalidates a still-valid access token immediately")
    void disablingRevokesLiveTokens() throws Exception {
        String token = accessTokenFor(MANAGER);
        assertOk(token);

        setFlag("enabled", false, MANAGER);

        mockMvc.perform(get("/api/v1/users").header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("locking an account invalidates a still-valid access token immediately")
    void lockingRevokesLiveTokens() throws Exception {
        String token = accessTokenFor(MANAGER);
        assertOk(token);

        setFlag("account_non_locked", false, MANAGER);

        mockMvc.perform(get("/api/v1/users").header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("a disabled account cannot log in, and the answer is indistinguishable from a wrong password")
    void disabledAccountCannotLogInAndLeaksNothing() throws Exception {
        setFlag("enabled", false, USER);

        String disabled = loginResponse(USER, DEMO_PASSWORD).getContentAsString();
        String wrongPassword = loginResponse(ADMIN, "Wrong1234!").getContentAsString();

        assertThat(loginResponse(USER, DEMO_PASSWORD).getStatus()).isEqualTo(401);
        assertThat(stripTimestampAndTrace(disabled))
                .as("account state is checked before the password, so a distinct "
                        + "message would reveal that the username exists")
                .isEqualTo(stripTimestampAndTrace(wrongPassword));
    }

    @Test
    @DisplayName("a locked account cannot log in")
    void lockedAccountCannotLogIn() throws Exception {
        setFlag("account_non_locked", false, USER);

        assertThat(loginResponse(USER, DEMO_PASSWORD).getStatus()).isEqualTo(401);
    }

    @Test
    @DisplayName("re-enabling an account restores access")
    void reEnablingRestoresAccess() throws Exception {
        setFlag("enabled", false, MANAGER);
        assertThat(loginResponse(MANAGER, DEMO_PASSWORD).getStatus()).isEqualTo(401);

        setFlag("enabled", true, MANAGER);
        assertOk(accessTokenFor(MANAGER));
    }

    @Test
    @DisplayName("the seeded SYSTEM auditor is disabled and cannot be logged into")
    void systemAccountIsNotLoginable() throws Exception {
        assertThat(jdbcTemplate.queryForObject(
                "SELECT enabled FROM users WHERE username = 'SYSTEM'", Boolean.class)).isFalse();

        assertThat(loginResponse("SYSTEM", DEMO_PASSWORD).getStatus()).isEqualTo(401);
    }

    private void assertOk(String token) throws Exception {
        mockMvc.perform(get("/api/v1/users").header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isOk());
    }

    /**
     * Flush first so the raw UPDATE runs against a consistent row, then clear the
     * persistence context: otherwise the next request would be served the cached
     * entity and never notice the flag changed.
     */
    private void setFlag(String column, boolean value, String username) {
        entityManager.flush();
        jdbcTemplate.update("UPDATE users SET " + column + " = ? WHERE username = ?", value, username);
        entityManager.clear();
    }

    /** Timestamps and trace ids differ per request; everything else must match. */
    private String stripTimestampAndTrace(String body) {
        return body.replaceAll("\"timestamp\":\"[^\"]*\",?", "")
                .replaceAll("\"traceId\":\"[^\"]*\",?", "");
    }
}
