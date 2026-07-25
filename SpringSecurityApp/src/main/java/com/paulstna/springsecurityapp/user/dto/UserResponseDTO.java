package com.paulstna.springsecurityapp.user.dto;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Getter
@Builder
public class UserResponseDTO {
    private UUID id;
    private String username;
    private Set<String> roles;
    private boolean enabled;
    private boolean accountNonLocked;
    private Instant createdAt;
    private Instant updatedAt;
}
