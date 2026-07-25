package com.paulstna.springsecurityapp.exception;

import com.paulstna.springsecurityapp.support.AbstractIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Transactional
@DisplayName("Request validation")
class ValidationIT extends AbstractIntegrationTest {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private UUID targetId;

    @BeforeEach
    void resolveTarget() {
        targetId = jdbcTemplate.queryForObject(
                "SELECT id FROM users WHERE username = ?", UUID.class, USER);
    }

    @ParameterizedTest(name = "username \"{0}\" is rejected")
    @ValueSource(strings = {"", "  ", "ab", "has space", "has!bang", "has/slash"})
    @DisplayName("registration rejects usernames that are blank, too short or oddly shaped")
    void invalidUsernamesAreRejected(String username) throws Exception {
        register(username, "Valid1234!")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Validation failed"))
                .andExpect(jsonPath("$.fieldErrors.username").exists());
    }

    @ParameterizedTest(name = "password \"{0}\" is rejected")
    @ValueSource(strings = {"", "Sh0rt!", "alllowercase1!", "ALLUPPERCASE1!", "NoDigitsHere!", "NoSpecial1234"})
    @DisplayName("registration enforces length and character-class rules on the password")
    void weakPasswordsAreRejected(String password) throws Exception {
        register("validname", password)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.password").exists());
    }

    @Test
    @DisplayName("a valid registration is accepted")
    void validRegistrationIsAccepted() throws Exception {
        register("perfectlyfine", "Valid1234!").andExpect(status().isCreated());
    }

    @Test
    @DisplayName("a password over BCrypt's 72-byte limit is rejected rather than silently truncated")
    void overlongPasswordIsRejected() throws Exception {
        register("longpass", "A1!" + "a".repeat(80))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.password").exists());
    }

    @Test
    @DisplayName("login only checks presence, so an existing weak password still works")
    void loginDoesNotApplyThePasswordPolicy() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                        .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credentials(ADMIN, "")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.password").exists());

        mockMvc.perform(post("/api/v1/auth/login")
                        .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credentials(ADMIN, "weak")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("creating a user requires a password")
    void passwordIsMandatoryOnCreate() throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"nopassword","roles":["USER"]}"""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.password").exists());
    }

    @Test
    @DisplayName("updating a user may omit the password to keep the current one")
    void passwordIsOptionalOnUpdate() throws Exception {
        mockMvc.perform(put("/api/v1/users/" + targetId)
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"user"}"""))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("updating still rejects a weak password when one is supplied")
    void updateStillEnforcesThePolicyWhenPasswordIsPresent() throws Exception {
        mockMvc.perform(put("/api/v1/users/" + targetId)
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"user","password":"weak"}"""))
                .andExpect(status().isBadRequest());
    }

    /** A null username used to reach setUsername(null) and blow up on a NOT NULL column. */
    @Test
    @DisplayName("updating without a username is a 400, not a 500")
    void updateWithoutUsernameIsRejected() throws Exception {
        mockMvc.perform(put("/api/v1/users/" + targetId)
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"password":"Valid1234!"}"""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.username").exists());
    }

    @ParameterizedTest(name = "{0} reports every broken rule at once")
    @CsvSource({"'',''"})
    @DisplayName("a request breaking several rules reports them all")
    void allFieldErrorsAreReported(String username, String password) throws Exception {
        register(username, password)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.username").exists())
                .andExpect(jsonPath("$.fieldErrors.password").exists());
    }

    private org.springframework.test.web.servlet.ResultActions register(String username, String password)
            throws Exception {
        return mockMvc.perform(post("/api/v1/auth/register")
                .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                .contentType(MediaType.APPLICATION_JSON)
                .content(credentials(username, password)));
    }
}
