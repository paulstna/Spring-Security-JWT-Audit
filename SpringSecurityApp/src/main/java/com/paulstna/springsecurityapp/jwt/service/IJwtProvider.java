package com.paulstna.springsecurityapp.jwt.service;

import com.paulstna.springsecurityapp.jwt.domain.TokenType;
import com.paulstna.springsecurityapp.user.domain.Role;
import io.jsonwebtoken.Claims;

import java.util.Set;

public interface IJwtProvider {
    String buildAccessJwt(String username, Set<Role> roles);

    String buildRefreshJwt(String username);

    String extractUsername(String token);

    TokenType extractTokenType(String token);

    boolean isJwtValid(String token);

    boolean isTokenExpired(String token);

    Claims extractAllClaims(String token);
}
