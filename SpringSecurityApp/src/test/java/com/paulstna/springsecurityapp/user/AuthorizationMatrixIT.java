package com.paulstna.springsecurityapp.user;

import com.paulstna.springsecurityapp.support.AbstractIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Transactional
@DisplayName("Authorization on /users")
class AuthorizationMatrixIT extends AbstractIntegrationTest {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private UUID targetId;

    @BeforeEach
    void resolveTarget() {
        targetId = jdbcTemplate.queryForObject(
                "SELECT id FROM users WHERE username = ?", UUID.class, USER);
    }

    @ParameterizedTest(name = "GET /users as {0} -> {1}")
    @CsvSource({"admin,200", "manager,200", "user,403"})
    @DisplayName("listing users requires MANAGER, which ADMIN inherits")
    void listRequiresManager(String username, int expected) throws Exception {
        mockMvc.perform(get("/api/v1/users").header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(username))))
                .andExpect(status().is(expected));
    }

    /**
     * Regression: these matchers used to be the exact collection path, so per-id
     * requests fell through to anyRequest().authenticated() and any logged-in user
     * could read or modify anyone else.
     */
    @ParameterizedTest(name = "GET /users/'{id}' as {0} -> {1}")
    @CsvSource({"admin,200", "manager,200", "user,403"})
    @DisplayName("reading a single user is protected too, not just the collection")
    void readByIdRequiresManager(String username, int expected) throws Exception {
        mockMvc.perform(get("/api/v1/users/" + targetId)
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(username))))
                .andExpect(status().is(expected));
    }

    @ParameterizedTest(name = "PUT /users/'{id}' as {0} -> {1}")
    @CsvSource({"admin,200", "manager,200", "user,403"})
    @DisplayName("updating a single user is protected too")
    void updateByIdRequiresManager(String username, int expected) throws Exception {
        mockMvc.perform(put("/api/v1/users/" + targetId)
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(username)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"user\"}"))
                .andExpect(status().is(expected));
    }

    @ParameterizedTest(name = "POST /users as {0} -> {1}")
    @CsvSource({"admin,201", "manager,403", "user,403"})
    @DisplayName("creating a user requires ADMIN")
    void createRequiresAdmin(String username, int expected) throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(username)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"created-by-%s","password":"Valid1234!","roles":["USER"]}"""
                                .formatted(username)))
                .andExpect(status().is(expected));
    }

    @ParameterizedTest(name = "DELETE /users/'{id}' as {0} -> {1}")
    @CsvSource({"manager,403", "user,403", "admin,204"})
    @DisplayName("deleting a user requires ADMIN")
    void deleteRequiresAdmin(String username, int expected) throws Exception {
        mockMvc.perform(delete("/api/v1/users/" + targetId)
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(username))))
                .andExpect(status().is(expected));
    }

    @Test
    @DisplayName("every /users endpoint refuses an anonymous caller")
    void anonymousIsRefusedEverywhere() throws Exception {
        mockMvc.perform(get("/api/v1/users")).andExpect(status().isForbidden());
        mockMvc.perform(get("/api/v1/users/" + targetId)).andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON)
                .content("{}")).andExpect(status().isForbidden());
        mockMvc.perform(delete("/api/v1/users/" + targetId)).andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("responses expose no password hash and no token collection")
    void responsesNeverLeakCredentials() throws Exception {
        String body = mockMvc.perform(get("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(MANAGER))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].username").exists())
                .andExpect(jsonPath("$[0].password").doesNotExist())
                .andExpect(jsonPath("$[0].tokens").doesNotExist())
                .andReturn().getResponse().getContentAsString();

        assertThat(body).doesNotContain("password").doesNotContain("bcrypt");
    }

    @Test
    @DisplayName("deleting a user leaves the shared role catalog untouched")
    void deletingAUserDoesNotCascadeIntoRoles() throws Exception {
        String adminToken = accessTokenFor(ADMIN);
        String created = mockMvc.perform(post("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(adminToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"doomed","password":"Valid1234!","roles":["MANAGER"]}"""))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        mockMvc.perform(delete("/api/v1/users/" + readString(created, "$.id"))
                        .header(HttpHeaders.AUTHORIZATION, bearer(adminToken)))
                .andExpect(status().isNoContent());

        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM roles", Integer.class))
                .as("cascading the delete into roles would strip that role from everyone")
                .isEqualTo(4);
        assertThat(jdbcTemplate.queryForList("""
                SELECT r.role_name FROM users u
                JOIN users_roles ur ON ur.user_id = u.id
                JOIN roles r ON r.id = ur.role_id WHERE u.username = ?""", String.class, MANAGER))
                .containsExactly("ROLE_MANAGER");
    }
}
