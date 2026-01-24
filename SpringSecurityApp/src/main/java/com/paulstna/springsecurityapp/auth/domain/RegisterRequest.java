package com.paulstna.springsecurityapp.auth.domain;

import lombok.Getter;

@Getter
public class RegisterRequest {
    private String username;
    private String password;
}
