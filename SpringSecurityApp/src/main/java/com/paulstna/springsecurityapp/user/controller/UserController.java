package com.paulstna.springsecurityapp.user.controller;

import com.paulstna.springsecurityapp.common.config.OpenApiConfig;
import com.paulstna.springsecurityapp.common.validation.ValidationGroups.OnCreate;
import com.paulstna.springsecurityapp.common.validation.ValidationGroups.OnUpdate;
import com.paulstna.springsecurityapp.exception.dto.ErrorResponseDTO;
import com.paulstna.springsecurityapp.user.dto.UserRequestDTO;
import com.paulstna.springsecurityapp.user.dto.UserResponseDTO;
import com.paulstna.springsecurityapp.user.mapper.UserMapper;
import com.paulstna.springsecurityapp.user.service.IUserEntityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping(path = "/api/{version}/users", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
@SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME)
@Tag(name = "Users",
        description = "User administration. Every operation needs an access token, and the "
                + "required role is stated per operation. Roles are hierarchical, so ADMIN "
                + "satisfies anything MANAGER can do.")
@ApiResponse(responseCode = "401", description = "No access token, or it is invalid or expired.",
        content = @Content(schema = @Schema(implementation = ErrorResponseDTO.class)))
@ApiResponse(responseCode = "403", description = "Authenticated, but the role is not enough.",
        content = @Content(schema = @Schema(implementation = ErrorResponseDTO.class)))
public class UserController {

    private final IUserEntityService userEntityService;

    @Operation(summary = "List every user", description = "Requires MANAGER.")
    @ApiResponse(responseCode = "200", description = "All users. Password hashes are never included.")
    @GetMapping(version = "v1")
    public ResponseEntity<List<UserResponseDTO>> findAll() {
        return ResponseEntity.ok(UserMapper.toResponseList(userEntityService.findAll()));
    }

    @Operation(summary = "Get one user", description = "Requires MANAGER.")
    @ApiResponse(responseCode = "200", description = "The user.")
    @ApiResponse(responseCode = "404", description = "No user with that id.",
            content = @Content(schema = @Schema(implementation = ErrorResponseDTO.class)))
    @GetMapping(path = "/{id}", version = "v1")
    public ResponseEntity<UserResponseDTO> findById(@PathVariable UUID id) {
        return ResponseEntity.ok(UserMapper.toResponse(userEntityService.findById(id)));
    }

    @Operation(summary = "Create a user",
            description = "Requires ADMIN. Roles may only be granted up to the caller's own "
                    + "level, so an ADMIN cannot mint a SYSTEM account. Omitting roles gives USER.")
    @ApiResponse(responseCode = "201", description = "User created.")
    @ApiResponse(responseCode = "400", description = "The payload breaks a validation rule.",
            content = @Content(schema = @Schema(implementation = ErrorResponseDTO.class)))
    @ApiResponse(responseCode = "404", description = "One of the requested roles does not exist.",
            content = @Content(schema = @Schema(implementation = ErrorResponseDTO.class)))
    @ApiResponse(responseCode = "409", description = "That username is already taken.",
            content = @Content(schema = @Schema(implementation = ErrorResponseDTO.class)))
    @PostMapping(version = "v1")
    public ResponseEntity<UserResponseDTO> create(
            @Validated(OnCreate.class) @RequestBody UserRequestDTO userRequestDTO) {
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(UserMapper.toResponse(userEntityService.createUser(userRequestDTO)));
    }

    @Operation(summary = "Update a user",
            description = "Requires MANAGER. Omit the password to keep the current one. The same "
                    + "ceiling on grantable roles applies as on create.")
    @ApiResponse(responseCode = "200", description = "User updated.")
    @ApiResponse(responseCode = "400", description = "The payload breaks a validation rule.",
            content = @Content(schema = @Schema(implementation = ErrorResponseDTO.class)))
    @ApiResponse(responseCode = "404", description = "No user with that id, or an unknown role.",
            content = @Content(schema = @Schema(implementation = ErrorResponseDTO.class)))
    @ApiResponse(responseCode = "409", description = "The new username is already taken.",
            content = @Content(schema = @Schema(implementation = ErrorResponseDTO.class)))
    @PutMapping(path = "/{id}", version = "v1")
    public ResponseEntity<UserResponseDTO> update(
            @PathVariable UUID id,
            @Validated(OnUpdate.class) @RequestBody UserRequestDTO userRequestDTO) {
        return ResponseEntity.ok(UserMapper.toResponse(userEntityService.update(id, userRequestDTO)));
    }

    @Operation(summary = "Delete a user",
            description = "Requires ADMIN. Deletes the account and its sessions. Roles are a "
                    + "shared catalogue and are left untouched.")
    @ApiResponse(responseCode = "204", description = "User deleted.")
    @ApiResponse(responseCode = "404", description = "No user with that id.",
            content = @Content(schema = @Schema(implementation = ErrorResponseDTO.class)))
    @DeleteMapping(path = "/{id}", version = "v1")
    public ResponseEntity<Void> delete(@PathVariable UUID id) {
        userEntityService.deleteById(id);
        return ResponseEntity.noContent().build();
    }

}
