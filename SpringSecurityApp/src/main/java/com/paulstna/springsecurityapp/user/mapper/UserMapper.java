package com.paulstna.springsecurityapp.user.mapper;

import com.paulstna.springsecurityapp.user.domain.UserEntity;
import com.paulstna.springsecurityapp.user.dto.UserResponseDTO;
import lombok.experimental.UtilityClass;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

@UtilityClass
public class UserMapper {

    public UserResponseDTO toResponse(UserEntity user) {
        return UserResponseDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .roles(toRoleNames(user))
                .enabled(user.isEnabled())
                .accountNonLocked(user.isAccountNonLocked())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }

    public List<UserResponseDTO> toResponseList(List<UserEntity> users) {
        return users.stream()
                .map(UserMapper::toResponse)
                .toList();
    }

    private Set<String> toRoleNames(UserEntity user) {
        return user.getRoles()
                .stream()
                .map(role -> role.getRoleName().name())
                // TreeSet keeps the role list stable across responses.
                .collect(Collectors.toCollection(TreeSet::new));
    }
}
