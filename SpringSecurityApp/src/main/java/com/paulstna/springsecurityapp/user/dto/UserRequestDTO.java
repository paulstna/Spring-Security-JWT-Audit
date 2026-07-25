package com.paulstna.springsecurityapp.user.dto;

import com.paulstna.springsecurityapp.common.validation.ValidationGroups.OnCreate;
import com.paulstna.springsecurityapp.common.validation.ValidationGroups.OnUpdate;
import com.paulstna.springsecurityapp.common.validation.ValidationRules;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;

import java.util.Set;

@Getter
@Schema(name = "UserRequest",
        description = "Payload for creating or updating a user. The password is required on "
                + "create and optional on update, where omitting it keeps the current one.")
public class UserRequestDTO {

    @Schema(example = "ada.lovelace", description = ValidationRules.USERNAME_MESSAGE)
    @NotBlank(message = "Username is required", groups = {OnCreate.class, OnUpdate.class})
    @Size(min = ValidationRules.USERNAME_MIN, max = ValidationRules.USERNAME_MAX,
            message = "Username must be between {min} and {max} characters",
            groups = {OnCreate.class, OnUpdate.class})
    @Pattern(regexp = ValidationRules.USERNAME_PATTERN, message = ValidationRules.USERNAME_MESSAGE,
            groups = {OnCreate.class, OnUpdate.class})
    private String username;

    // Required only on create: an update omits it to keep the current password.
    // @Size and @Pattern skip null values, so an omitted password stays valid.
    @Schema(example = "Str0ng!Pass", format = "password",
            description = ValidationRules.PASSWORD_MESSAGE + ". Omit on update to keep the current one.")
    @NotBlank(message = "Password is required", groups = OnCreate.class)
    @Size(min = ValidationRules.PASSWORD_MIN, max = ValidationRules.PASSWORD_MAX,
            message = "Password must be between {min} and {max} characters",
            groups = {OnCreate.class, OnUpdate.class})
    @Pattern(regexp = ValidationRules.PASSWORD_PATTERN, message = ValidationRules.PASSWORD_MESSAGE,
            groups = {OnCreate.class, OnUpdate.class})
    private String password;

    @Schema(description = "Role names, with or without the ROLE_ prefix. Only roles at or below "
            + "the caller's own level may be granted, so SYSTEM is never assignable. "
            + "Omit for a plain USER.",
            example = "[\"MANAGER\"]")
    private Set<String> roles;
}
