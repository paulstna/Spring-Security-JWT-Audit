package com.paulstna.springsecurityapp.user.dto;

import lombok.Getter;
import java.util.Set;

@Getter
public class UserDto {
    private String username;
    private String password;
    private Set<String> roles;
}
