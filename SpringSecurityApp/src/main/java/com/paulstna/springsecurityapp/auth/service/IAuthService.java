package com.paulstna.springsecurityapp.auth.service;

import com.paulstna.springsecurityapp.auth.dto.AuthInternalResponseDto;
import com.paulstna.springsecurityapp.auth.domain.LoginRequest;
import com.paulstna.springsecurityapp.auth.domain.RegisterRequest;

public interface IAuthService {
    AuthInternalResponseDto register(RegisterRequest registerRequest, String userAgent, String ip);

    AuthInternalResponseDto login(LoginRequest loginRequest, String userAgent, String ip);

    void logout(String refreshToken);

    AuthInternalResponseDto refreshToken(String refreshToken, String userAgent, String ip);
}
