package com.paulstna.springsecurityapp.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class AuthInternalResponseDto {
    private String authToken;
    private String refreshToken;
}
