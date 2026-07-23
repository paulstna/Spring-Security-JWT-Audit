package com.paulstna.springsecurityapp.user.controller;

import com.paulstna.springsecurityapp.user.domain.UserEntity;
import com.paulstna.springsecurityapp.user.dto.UserDto;
import com.paulstna.springsecurityapp.user.service.IUserEntityService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/{version}/users")
@RequiredArgsConstructor
public class UserController {

    private final IUserEntityService userEntityService;

    @GetMapping(version = "v1")
    public ResponseEntity<List<UserEntity>> findAll() {
        return ResponseEntity.ok(userEntityService.findAll());
    }

    @GetMapping(path = "/{id}", version = "v1")
    public ResponseEntity<UserEntity> findById(@PathVariable UUID id) {
        return ResponseEntity.ok(userEntityService.findById(id));
    }

    @PostMapping(version = "v1")
    public ResponseEntity<UserEntity> create(@RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userEntityService.createUser(userDto));
    }

    @PutMapping(path = "/{id}", version = "v1")
    public ResponseEntity<UserEntity> update(@PathVariable UUID id, @RequestBody UserDto userDto) {
        return ResponseEntity.ok(userEntityService.update(id, userDto));
    }

    @DeleteMapping(path = "/{id}", version = "v1")
    public ResponseEntity<Void> delete(@PathVariable UUID id) {
        userEntityService.deleteById(id);
        return ResponseEntity.noContent().build();
    }

}
