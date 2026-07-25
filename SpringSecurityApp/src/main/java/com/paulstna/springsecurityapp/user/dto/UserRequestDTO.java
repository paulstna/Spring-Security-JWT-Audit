package com.paulstna.springsecurityapp.user.dto;

import com.paulstna.springsecurityapp.common.validation.ValidationGroups.OnCreate;
import com.paulstna.springsecurityapp.common.validation.ValidationGroups.OnUpdate;
import com.paulstna.springsecurityapp.common.validation.ValidationRules;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;

import java.util.Set;

@Getter
public class UserRequestDTO {

    @NotBlank(message = "Username is required", groups = {OnCreate.class, OnUpdate.class})
    @Size(min = ValidationRules.USERNAME_MIN, max = ValidationRules.USERNAME_MAX,
            message = "Username must be between {min} and {max} characters",
            groups = {OnCreate.class, OnUpdate.class})
    @Pattern(regexp = ValidationRules.USERNAME_PATTERN, message = ValidationRules.USERNAME_MESSAGE,
            groups = {OnCreate.class, OnUpdate.class})
    private String username;

    // Required only on create: an update omits it to keep the current password.
    // @Size and @Pattern skip null values, so an omitted password stays valid.
    @NotBlank(message = "Password is required", groups = OnCreate.class)
    @Size(min = ValidationRules.PASSWORD_MIN, max = ValidationRules.PASSWORD_MAX,
            message = "Password must be between {min} and {max} characters",
            groups = {OnCreate.class, OnUpdate.class})
    @Pattern(regexp = ValidationRules.PASSWORD_PATTERN, message = ValidationRules.PASSWORD_MESSAGE,
            groups = {OnCreate.class, OnUpdate.class})
    private String password;

    private Set<String> roles;
}
