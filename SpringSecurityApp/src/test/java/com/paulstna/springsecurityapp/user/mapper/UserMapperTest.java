package com.paulstna.springsecurityapp.user.mapper;

import com.paulstna.springsecurityapp.user.domain.Role;
import com.paulstna.springsecurityapp.user.domain.RoleName;
import com.paulstna.springsecurityapp.user.domain.UserEntity;
import com.paulstna.springsecurityapp.user.dto.UserResponseDTO;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("UserMapper")
class UserMapperTest {

    private UserEntity user(String username, boolean enabled, RoleName... roles) {
        UserEntity entity = new UserEntity();
        entity.setId(UUID.randomUUID());
        entity.setUsername(username);
        entity.setPassword("{bcrypt}$2a$10$averysecrethashthatmustneverleak");
        entity.setEnabled(enabled);
        entity.setAccountNonLocked(true);
        entity.setCreatedAt(Instant.parse("2026-01-01T00:00:00Z"));
        entity.setUpdatedAt(Instant.parse("2026-02-01T00:00:00Z"));
        entity.setRoles(java.util.Arrays.stream(roles)
                .map(name -> new Role(null, name))
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new)));
        return entity;
    }

    @Test
    @DisplayName("copies the fields a client is allowed to see")
    void copiesVisibleFields() {
        UserEntity entity = user("alice", true, RoleName.ROLE_ADMIN);

        UserResponseDTO dto = UserMapper.toResponse(entity);

        assertThat(dto.getId()).isEqualTo(entity.getId());
        assertThat(dto.getUsername()).isEqualTo("alice");
        assertThat(dto.isEnabled()).isTrue();
        assertThat(dto.isAccountNonLocked()).isTrue();
        assertThat(dto.getCreatedAt()).isEqualTo(Instant.parse("2026-01-01T00:00:00Z"));
        assertThat(dto.getUpdatedAt()).isEqualTo(Instant.parse("2026-02-01T00:00:00Z"));
        assertThat(dto.getRoles()).containsExactly("ROLE_ADMIN");
    }

    /** The whole reason the DTO exists: the entity used to be serialised as-is. */
    @Test
    @DisplayName("exposes no password field at all, not even an empty one")
    void hasNoPasswordField() {
        assertThat(List.of(UserResponseDTO.class.getDeclaredFields()).stream().map(Field::getName))
                .doesNotContain("password", "tokens");
    }

    @Test
    @DisplayName("orders roles so responses are stable between calls")
    void rolesAreOrdered() {
        UserEntity entity = user("bob", true,
                RoleName.ROLE_USER, RoleName.ROLE_ADMIN, RoleName.ROLE_MANAGER);

        assertThat(UserMapper.toResponse(entity).getRoles())
                .containsExactly("ROLE_ADMIN", "ROLE_MANAGER", "ROLE_USER");
    }

    @Test
    @DisplayName("reports a disabled account as disabled")
    void reflectsAccountState() {
        assertThat(UserMapper.toResponse(user("carol", false, RoleName.ROLE_USER)).isEnabled()).isFalse();
    }

    @Test
    @DisplayName("maps a whole list, preserving order")
    void mapsLists() {
        List<UserResponseDTO> mapped = UserMapper.toResponseList(List.of(
                user("alice", true, RoleName.ROLE_ADMIN),
                user("bob", true, RoleName.ROLE_USER)));

        assertThat(mapped).extracting(UserResponseDTO::getUsername).containsExactly("alice", "bob");
    }

    @Test
    @DisplayName("handles a user with no roles without failing")
    void handlesEmptyRoles() {
        UserEntity entity = user("dave", true);
        entity.setRoles(Set.of());

        assertThat(UserMapper.toResponse(entity).getRoles()).isEmpty();
    }
}
