package com.paulstna.springsecurityapp.auth.domain;

import com.paulstna.springsecurityapp.common.validation.ValidationRules;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;

@Getter
public class RegisterRequest {

    @NotBlank(message = "Username is required")
    @Size(min = ValidationRules.USERNAME_MIN, max = ValidationRules.USERNAME_MAX,
            message = "Username must be between {min} and {max} characters")
    @Pattern(regexp = ValidationRules.USERNAME_PATTERN, message = ValidationRules.USERNAME_MESSAGE)
    private String username;

    @NotBlank(message = "Password is required")
    @Size(min = ValidationRules.PASSWORD_MIN, max = ValidationRules.PASSWORD_MAX,
            message = "Password must be between {min} and {max} characters")
    @Pattern(regexp = ValidationRules.PASSWORD_PATTERN, message = ValidationRules.PASSWORD_MESSAGE)
    private String password;
}
