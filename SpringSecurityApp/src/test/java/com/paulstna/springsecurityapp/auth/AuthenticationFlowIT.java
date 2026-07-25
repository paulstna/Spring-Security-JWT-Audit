package com.paulstna.springsecurityapp.auth;

import com.paulstna.springsecurityapp.jwt.util.TokenHasher;
import com.paulstna.springsecurityapp.support.AbstractIntegrationTest;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Transactional
@DisplayName("Authentication flow")
class AuthenticationFlowIT extends AbstractIntegrationTest {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @jakarta.persistence.PersistenceContext
    private jakarta.persistence.EntityManager entityManager;

    /**
     * The test method and the service share one transaction, so JPA writes sit in
     * the persistence context until commit. Raw SQL bypasses that context, so it
     * has to be flushed first or the assertions would read a stale database.
     */
    private void flushPendingWrites() {
        entityManager.flush();
    }

    @Test
    @DisplayName("register issues an access token, sets the refresh cookie and stores the session")
    void registerIssuesTokensAndPersistsSession() throws Exception {
        MockHttpServletResponse response = register("newcomer", "Valid1234!");

        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(readString(response.getContentAsString(), "$.authToken")).isNotBlank();

        Cookie cookie = response.getCookie("refreshToken");
        assertThat(cookie).isNotNull();
        assertThat(cookie.isHttpOnly()).as("refresh cookie must be unreadable from JavaScript").isTrue();
        assertThat(cookie.getPath())
                .as("must cover /logout too, not only /refresh")
                .isEqualTo("/api/v1/auth");

        assertThat(sessionCountFor("newcomer"))
                .as("register must persist the refresh token, not drop it")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("register grants only ROLE_USER, never a role of the caller's choosing")
    void selfRegistrationCannotPickItsRole() throws Exception {
        register("selfmade", "Valid1234!");

        assertThat(rolesOf("selfmade")).containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("register rejects a username that already exists")
    void registerRejectsDuplicateUsername() throws Exception {
        register("twice", "Valid1234!");

        mockMvc.perform(post("/api/v1/auth/register")
                        .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credentials("twice", "Valid1234!")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409));
    }

    @Test
    @DisplayName("login succeeds with the right password and fails identically for every other case")
    void loginOutcomes() throws Exception {
        assertThat(loginResponse(ADMIN, DEMO_PASSWORD).getStatus()).isEqualTo(200);

        MockHttpServletResponse wrongPassword = loginResponse(ADMIN, "Wrong1234!");
        MockHttpServletResponse unknownUser = loginResponse("no-such-user", "Wrong1234!");

        assertThat(wrongPassword.getStatus()).isEqualTo(401);
        assertThat(unknownUser.getStatus()).isEqualTo(401);
        assertThat(unknownUser.getContentAsString())
                .as("a different message would let an attacker enumerate usernames")
                .contains("Bad credentials");
    }

    @Test
    @DisplayName("logging in again replaces the previous session for the same User-Agent")
    void loginSupersedesPreviousSessionOnSameDevice() throws Exception {
        String first = refreshTokenFor(MANAGER);
        String second = refreshTokenFor(MANAGER);

        assertThat(first).isNotEqualTo(second);
        assertThat(sessionCountFor(MANAGER)).isEqualTo(1);
        assertThat(refresh(first).getStatus())
                .as("the superseded token must no longer work")
                .isEqualTo(401);
        assertThat(refresh(second).getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("refresh rotates the token and invalidates the one just used")
    void refreshRotatesTheToken() throws Exception {
        String original = refreshTokenFor(USER);

        MockHttpServletResponse rotated = refresh(original);
        assertThat(rotated.getStatus()).isEqualTo(200);

        String replacement = refreshCookieValue(rotated);
        assertThat(replacement).isNotEqualTo(original);
        assertThat(sessionCountFor(USER)).as("rotation replaces, it does not accumulate").isEqualTo(1);

        assertThat(refresh(original).getStatus())
                .as("replaying a rotated token must fail")
                .isEqualTo(401);
    }

    @Test
    @DisplayName("refresh is refused when the cookie is missing, malformed or from another device")
    void refreshRejectsBadInput() throws Exception {
        assertThat(mockMvc.perform(post("/api/v1/auth/refresh")
                        .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT))
                .andReturn().getResponse().getStatus())
                .as("no cookie at all is a bad request, not an auth failure")
                .isEqualTo(400);

        assertThat(refresh("not.a.jwt").getStatus()).isEqualTo(401);

        String token = refreshTokenFor(ADMIN);
        assertThat(mockMvc.perform(post("/api/v1/auth/refresh")
                        .header(HttpHeaders.USER_AGENT, "a-completely-different-agent/2.0")
                        .cookie(new Cookie("refreshToken", token)))
                .andReturn().getResponse().getStatus())
                .as("a stolen cookie replayed from another device must be refused")
                .isEqualTo(401);
    }

    @Test
    @DisplayName("logout deletes the stored session and is safe to repeat")
    void logoutIsIdempotent() throws Exception {
        String token = refreshTokenFor(MANAGER);

        assertThat(logout(token).getStatus()).isEqualTo(204);
        assertThat(sessionCountFor(MANAGER)).isEqualTo(0);

        assertThat(logout(token).getStatus()).as("logging out twice is not an error").isEqualTo(204);
        assertThat(mockMvc.perform(post("/api/v1/auth/logout")
                        .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT))
                .andReturn().getResponse().getStatus())
                .as("logging out without a cookie is not an error either")
                .isEqualTo(204);
    }

    @Test
    @DisplayName("only the hash of a refresh token is stored, never the token itself")
    void refreshTokensAreStoredHashed() throws Exception {
        String token = refreshTokenFor(ADMIN);
        flushPendingWrites();

        String stored = jdbcTemplate.queryForObject("""
                SELECT t.token_hash FROM tokens t
                JOIN users u ON u.id = t.user_id WHERE u.username = ?""", String.class, ADMIN);

        assertThat(stored).isEqualTo(TokenHasher.hash(token));
        assertThat(stored).hasSize(64).doesNotContain(".");
        assertThat(token).as("the raw JWT must never reach the database").isNotEqualTo(stored);
    }

    private MockHttpServletResponse register(String username, String password) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/register")
                        .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credentials(username, password)))
                .andReturn()
                .getResponse();
    }

    private MockHttpServletResponse refresh(String refreshToken) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/refresh")
                        .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                        .cookie(new Cookie("refreshToken", refreshToken)))
                .andReturn()
                .getResponse();
    }

    private MockHttpServletResponse logout(String refreshToken) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/logout")
                        .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                        .cookie(new Cookie("refreshToken", refreshToken)))
                .andReturn()
                .getResponse();
    }

    private Integer sessionCountFor(String username) {
        flushPendingWrites();
        return jdbcTemplate.queryForObject("""
                SELECT count(*) FROM tokens t
                JOIN users u ON u.id = t.user_id WHERE u.username = ?""", Integer.class, username);
    }

    private java.util.List<String> rolesOf(String username) {
        flushPendingWrites();
        return jdbcTemplate.queryForList("""
                SELECT r.role_name FROM users u
                JOIN users_roles ur ON ur.user_id = u.id
                JOIN roles r ON r.id = ur.role_id WHERE u.username = ?""", String.class, username);
    }
}
