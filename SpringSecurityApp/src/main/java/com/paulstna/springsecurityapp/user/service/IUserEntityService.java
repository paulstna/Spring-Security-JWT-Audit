package com.paulstna.springsecurityapp.user.service;

import com.paulstna.springsecurityapp.auth.domain.RegisterRequest;
import com.paulstna.springsecurityapp.user.domain.UserEntity;
import com.paulstna.springsecurityapp.user.dto.UserDto;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface IUserEntityService {
    UserEntity buildUserEntityFromRequest(RegisterRequest request);

    UserEntity createUser(UserDto userDto);

    UserEntity save(UserEntity user);

    UserEntity findById(UUID id);

    Optional<UserEntity> findByUsername(String username);

    List<UserEntity> findAll();

    UserEntity update(UUID id, UserDto request);

    void deleteById(UUID id);
}
