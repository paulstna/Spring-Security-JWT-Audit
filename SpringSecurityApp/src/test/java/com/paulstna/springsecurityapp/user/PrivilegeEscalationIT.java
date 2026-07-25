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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Transactional
@DisplayName("Privilege escalation")
class PrivilegeEscalationIT extends AbstractIntegrationTest {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private UUID targetId;

    @BeforeEach
    void resolveTarget() {
        targetId = jdbcTemplate.queryForObject(
                "SELECT id FROM users WHERE username = ?", UUID.class, USER);
    }

    @Test
    @DisplayName("nobody can grant ROLE_SYSTEM, not even an admin")
    void systemRoleIsNeverGrantable() throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"wannabe","password":"Valid1234!","roles":["SYSTEM"]}"""))
                .andExpect(status().isForbidden())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("ROLE_SYSTEM is reserved")));
    }

    @Test
    @DisplayName("a manager cannot mint an admin")
    void callerCannotGrantARoleAboveItsOwn() throws Exception {
        mockMvc.perform(put("/api/v1/users/" + targetId)
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(MANAGER)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"user","roles":["ADMIN"]}"""))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value(
                        org.hamcrest.Matchers.containsString("Cannot grant a role you do not hold")));
    }

    @ParameterizedTest(name = "manager granting {0} -> {1}")
    @CsvSource({"MANAGER,200", "USER,200", "ADMIN,403", "SYSTEM,403"})
    @DisplayName("a caller may grant its own role and anything below it")
    void managerMayGrantAtOrBelowItsOwnLevel(String role, int expected) throws Exception {
        mockMvc.perform(put("/api/v1/users/" + targetId)
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(MANAGER)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"user","roles":["%s"]}""".formatted(role)))
                .andExpect(status().is(expected));
    }

    @ParameterizedTest(name = "admin granting {0} -> {1}")
    @CsvSource({"ADMIN,201", "MANAGER,201", "USER,201", "SYSTEM,403"})
    @DisplayName("an admin may grant everything except SYSTEM")
    void adminMayGrantEverythingBelowSystem(String role, int expected) throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"granted-%s","password":"Valid1234!","roles":["%s"]}"""
                                .formatted(role.toLowerCase(), role)))
                .andExpect(status().is(expected));
    }

    @Test
    @DisplayName("an unknown role name is a 404, not a 500")
    void unknownRoleIsNotFound() throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"wizardly","password":"Valid1234!","roles":["WIZARD"]}"""))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("Role not found: ROLE_WIZARD"));
    }

    @Test
    @DisplayName("a rejected escalation creates no user at all")
    void rejectedEscalationIsNotPartiallyApplied() throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"ghostuser","password":"Valid1234!","roles":["SYSTEM"]}"""))
                .andExpect(status().isForbidden());

        org.assertj.core.api.Assertions.assertThat(jdbcTemplate.queryForObject(
                        "SELECT count(*) FROM users WHERE username = 'ghostuser'", Integer.class))
                .isZero();
    }
}
