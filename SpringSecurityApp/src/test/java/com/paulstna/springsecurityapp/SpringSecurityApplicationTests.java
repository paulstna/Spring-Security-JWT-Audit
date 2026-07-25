package com.paulstna.springsecurityapp;

import com.paulstna.springsecurityapp.support.AbstractIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Application context")
class SpringSecurityApplicationTests extends AbstractIntegrationTest {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    @DisplayName("starts against a real PostgreSQL and applies every migration")
    void contextLoadsAndMigrationsApply() {
        Integer applied = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM flyway_schema_history WHERE success", Integer.class);

        // Booting at all proves ddl-auto=validate accepted the migrated schema.
        assertThat(applied).isEqualTo(4);
    }

    @Test
    @DisplayName("seeds the SYSTEM auditor plus the three demo accounts")
    void seedDataIsPresent() {
        assertThat(jdbcTemplate.queryForList(
                "SELECT username FROM users ORDER BY username", String.class))
                .containsExactly("SYSTEM", "admin", "manager", "user");

        assertThat(jdbcTemplate.queryForObject(
                "SELECT enabled FROM users WHERE username = 'SYSTEM'", Boolean.class))
                .as("the SYSTEM auditor must never be able to log in")
                .isFalse();

        assertThat(jdbcTemplate.queryForList(
                "SELECT role_name FROM roles ORDER BY id", String.class))
                .containsExactly("ROLE_SYSTEM", "ROLE_ADMIN", "ROLE_MANAGER", "ROLE_USER");
    }
}
