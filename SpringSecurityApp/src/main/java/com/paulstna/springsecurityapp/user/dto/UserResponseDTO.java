package com.paulstna.springsecurityapp.user.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Getter
@Builder
@Schema(name = "UserResponse",
        description = "A user as the API exposes it. Deliberately not the entity: the password "
                + "hash and the session tokens have no field here to leak through.")
public class UserResponseDTO {

    @Schema(example = "6c2f1b7e-6f1a-4c3e-9f4a-2b8d5c1e7a90")
    private UUID id;

    @Schema(example = "ada.lovelace")
    private String username;

    @Schema(description = "Granted roles, always prefixed with ROLE_.",
            example = "[\"ROLE_MANAGER\"]")
    private Set<String> roles;

    @Schema(description = "A disabled account cannot sign in, and its live tokens stop working.")
    private boolean enabled;

    @Schema(description = "False once the account is locked. Same effect as disabling, "
            + "different reason in the audit trail.")
    private boolean accountNonLocked;

    private Instant createdAt;
    private Instant updatedAt;
}
