package com.paulstna.springsecurityapp.security.authorization;

import com.paulstna.springsecurityapp.user.domain.RoleName;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("RoleAuthorizationService")
class RoleAuthorizationServiceImplTest {

    /** Mirrors the hierarchy declared in SecurityConfig. */
    private static final RoleHierarchy HIERARCHY = RoleHierarchyImpl.withDefaultRolePrefix()
            .role("SYSTEM").implies("ADMIN")
            .role("ADMIN").implies("MANAGER")
            .role("MANAGER").implies("USER")
            .build();

    private final RoleAuthorizationServiceImpl service = new RoleAuthorizationServiceImpl(HIERARCHY);

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private void authenticateAs(String authority) {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("caller", null,
                        List.of(new SimpleGrantedAuthority(authority))));
    }

    @ParameterizedTest(name = "{0} may not be granted, whoever asks")
    @EnumSource(value = RoleName.class, names = "ROLE_SYSTEM")
    @DisplayName("ROLE_SYSTEM is reserved for the auditor and is never grantable")
    void systemIsNeverGrantable(RoleName reserved) {
        authenticateAs("ROLE_SYSTEM");

        assertThatThrownBy(() -> service.ensureCallerCanGrant(reserved))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("reserved for auditing");
    }

    @Test
    @DisplayName("an admin may grant its own role and everything below it")
    void adminMayGrantAtOrBelowItself() {
        authenticateAs("ROLE_ADMIN");

        assertThatCode(() -> service.ensureCallerCanGrant(RoleName.ROLE_ADMIN)).doesNotThrowAnyException();
        assertThatCode(() -> service.ensureCallerCanGrant(RoleName.ROLE_MANAGER)).doesNotThrowAnyException();
        assertThatCode(() -> service.ensureCallerCanGrant(RoleName.ROLE_USER)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a manager cannot grant a role above its own")
    void managerCannotGrantAdmin() {
        authenticateAs("ROLE_MANAGER");

        assertThatThrownBy(() -> service.ensureCallerCanGrant(RoleName.ROLE_ADMIN))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Cannot grant a role you do not hold");

        assertThatCode(() -> service.ensureCallerCanGrant(RoleName.ROLE_MANAGER)).doesNotThrowAnyException();
        assertThatCode(() -> service.ensureCallerCanGrant(RoleName.ROLE_USER)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a plain user cannot grant anything above USER")
    void userCannotGrantUpwards() {
        authenticateAs("ROLE_USER");

        assertThatThrownBy(() -> service.ensureCallerCanGrant(RoleName.ROLE_MANAGER))
                .isInstanceOf(AccessDeniedException.class);
        assertThatCode(() -> service.ensureCallerCanGrant(RoleName.ROLE_USER)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("with no authenticated caller nothing may be granted")
    void anonymousMayGrantNothing() {
        SecurityContextHolder.clearContext();

        assertThatThrownBy(() -> service.ensureCallerCanGrant(RoleName.ROLE_USER))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("without an authenticated caller");
    }
}
