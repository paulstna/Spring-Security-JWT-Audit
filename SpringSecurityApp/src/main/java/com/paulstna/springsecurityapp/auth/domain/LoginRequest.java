package com.paulstna.springsecurityapp.auth.domain;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
@Schema(description = "Credentials. No format rules are applied here on purpose: rejecting a "
        + "malformed username early would tell an attacker it cannot exist.")
public class LoginRequest {

    @NotBlank(message = "Username is required")
    @Schema(example = "admin")
    private String username;

    @NotBlank(message = "Password is required")
    @Schema(example = "Demo1234!", format = "password")
    private String password;
}
