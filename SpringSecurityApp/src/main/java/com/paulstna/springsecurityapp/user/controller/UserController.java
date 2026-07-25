package com.paulstna.springsecurityapp.user.controller;

import com.paulstna.springsecurityapp.common.validation.ValidationGroups.OnCreate;
import com.paulstna.springsecurityapp.common.validation.ValidationGroups.OnUpdate;
import com.paulstna.springsecurityapp.user.dto.UserRequestDTO;
import com.paulstna.springsecurityapp.user.dto.UserResponseDTO;
import com.paulstna.springsecurityapp.user.mapper.UserMapper;
import com.paulstna.springsecurityapp.user.service.IUserEntityService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/{version}/users")
@RequiredArgsConstructor
public class UserController {

    private final IUserEntityService userEntityService;

    @GetMapping(version = "v1")
    public ResponseEntity<List<UserResponseDTO>> findAll() {
        return ResponseEntity.ok(UserMapper.toResponseList(userEntityService.findAll()));
    }

    @GetMapping(path = "/{id}", version = "v1")
    public ResponseEntity<UserResponseDTO> findById(@PathVariable UUID id) {
        return ResponseEntity.ok(UserMapper.toResponse(userEntityService.findById(id)));
    }

    @PostMapping(version = "v1")
    public ResponseEntity<UserResponseDTO> create(
            @Validated(OnCreate.class) @RequestBody UserRequestDTO userRequestDTO) {
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(UserMapper.toResponse(userEntityService.createUser(userRequestDTO)));
    }

    @PutMapping(path = "/{id}", version = "v1")
    public ResponseEntity<UserResponseDTO> update(
            @PathVariable UUID id,
            @Validated(OnUpdate.class) @RequestBody UserRequestDTO userRequestDTO) {
        return ResponseEntity.ok(UserMapper.toResponse(userEntityService.update(id, userRequestDTO)));
    }

    @DeleteMapping(path = "/{id}", version = "v1")
    public ResponseEntity<Void> delete(@PathVariable UUID id) {
        userEntityService.deleteById(id);
        return ResponseEntity.noContent().build();
    }

}
