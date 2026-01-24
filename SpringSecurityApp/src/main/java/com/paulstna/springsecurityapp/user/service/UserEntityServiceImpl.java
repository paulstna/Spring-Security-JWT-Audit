package com.paulstna.springsecurityapp.user.service;

import com.paulstna.springsecurityapp.auth.domain.RegisterRequest;
import com.paulstna.springsecurityapp.exception.ResourceAlreadyExistsException;
import com.paulstna.springsecurityapp.exception.ResourceNotFoundException;
import com.paulstna.springsecurityapp.user.domain.Role;
import com.paulstna.springsecurityapp.user.domain.RoleName;
import com.paulstna.springsecurityapp.user.domain.UserEntity;
import com.paulstna.springsecurityapp.user.dto.UserDto;
import com.paulstna.springsecurityapp.user.repository.RoleRepository;
import com.paulstna.springsecurityapp.user.repository.UserEntityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserEntityServiceImpl implements IUserEntityService {
    private final UserEntityRepository userEntityRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;

    @Override
    public UserEntity buildUserEntityFromRequest(RegisterRequest request) {
        validateUsernameNotExists(request.getUsername());

        UserEntity user = new UserEntity();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        user.getRoles().add(getDefaultRole());
        return user;
    }

    @Override
    public UserEntity createUser(UserDto userDto) {
        validateUsernameNotExists(userDto.getUsername());

        UserEntity user = new UserEntity();
        user.setUsername(userDto.getUsername());
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));

        Set<Role> roles = resolveRoles(userDto.getRoles());
        user.setRoles(roles);

        return userEntityRepository.save(user);
    }

    @Override
    public UserEntity save(UserEntity user) {
        return userEntityRepository.save(user);
    }

    @Override
    public UserEntity findById(UUID id) {
        return userEntityRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    @Override
    public Optional<UserEntity> findByUsername(String username) {
        return userEntityRepository.findByUsername(username);
    }

    @Override
    public List<UserEntity> findAll() {
        return userEntityRepository.findAll();
    }

    @Override
    public UserEntity update(UUID id, UserDto request) {
        UserEntity user = findById(id);

        if (!user.getUsername().equals(request.getUsername())) {
            validateUsernameNotExists(request.getUsername());
            user.setUsername(request.getUsername());
        }

        if (StringUtils.hasText(request.getPassword())) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }

        if (request.getRoles() != null && !request.getRoles().isEmpty()) {
            Set<Role> roles = resolveRoles(request.getRoles());
            user.setRoles(roles);
        }

        return userEntityRepository.save(user);
    }

    @Override
    public void deleteById(UUID id) {
        if (!userEntityRepository.existsById(id)) {
            throw new ResourceNotFoundException("User not found with id: " + id);
        }
        userEntityRepository.deleteById(id);
    }

    private void validateUsernameNotExists(String username) {
        if (userEntityRepository.existsByUsername(username)) {
            throw new ResourceAlreadyExistsException("Username already exists: " + username);
        }
    }

    private Role getDefaultRole() {
        return roleRepository.findByRoleName(RoleName.ROLE_USER)
                .orElseThrow(() -> new ResourceNotFoundException("Default role not found"));
    }

    private Set<Role> resolveRoles(Set<String> roleNames) {
        if (roleNames == null || roleNames.isEmpty()) {
            return new HashSet<>(Set.of(getDefaultRole()));
        }

        return roleNames.stream()
                .map(this::findRoleByName)
                .collect(Collectors.toSet());
    }

    private Role findRoleByName(String roleName) {
        String normalizedName = roleName.toUpperCase().startsWith("ROLE_")
                ? roleName.toUpperCase()
                : "ROLE_" + roleName.toUpperCase();

        return roleRepository.findByRoleName(RoleName.valueOf(normalizedName))
                .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + normalizedName));
    }

}
