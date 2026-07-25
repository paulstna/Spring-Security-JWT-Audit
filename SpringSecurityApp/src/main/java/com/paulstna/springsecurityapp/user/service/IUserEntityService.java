package com.paulstna.springsecurityapp.user.service;

import com.paulstna.springsecurityapp.auth.domain.RegisterRequest;
import com.paulstna.springsecurityapp.user.domain.UserEntity;
import com.paulstna.springsecurityapp.user.dto.UserRequestDTO;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface IUserEntityService {
    UserEntity buildUserEntityFromRequest(RegisterRequest request);

    UserEntity createUser(UserRequestDTO userRequestDTO);

    UserEntity save(UserEntity user);

    UserEntity findById(UUID id);

    Optional<UserEntity> findByUsername(String username);

    List<UserEntity> findAll();

    UserEntity update(UUID id, UserRequestDTO request);

    void deleteById(UUID id);
}
