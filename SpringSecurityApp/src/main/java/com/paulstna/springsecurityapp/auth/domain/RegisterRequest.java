package com.paulstna.springsecurityapp.auth.domain;

import com.paulstna.springsecurityapp.common.validation.ValidationRules;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;

@Getter
@Schema(description = "A new account. It always gets the USER role; roles cannot be requested here.")
public class RegisterRequest {

    @NotBlank(message = "Username is required")
    @Size(min = ValidationRules.USERNAME_MIN, max = ValidationRules.USERNAME_MAX,
            message = "Username must be between {min} and {max} characters")
    @Pattern(regexp = ValidationRules.USERNAME_PATTERN, message = ValidationRules.USERNAME_MESSAGE)
    @Schema(description = ValidationRules.USERNAME_MESSAGE, example = "ada.lovelace")
    private String username;

    @NotBlank(message = "Password is required")
    @Size(min = ValidationRules.PASSWORD_MIN, max = ValidationRules.PASSWORD_MAX,
            message = "Password must be between {min} and {max} characters")
    @Pattern(regexp = ValidationRules.PASSWORD_PATTERN, message = ValidationRules.PASSWORD_MESSAGE)
    @Schema(description = ValidationRules.PASSWORD_MESSAGE
            + ". Capped at 72 bytes because BCrypt silently ignores anything past that.",
            example = "Str0ng!Pass", format = "password")
    private String password;
}
