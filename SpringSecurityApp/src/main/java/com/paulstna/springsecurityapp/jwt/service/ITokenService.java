package com.paulstna.springsecurityapp.jwt.service;

import com.paulstna.springsecurityapp.jwt.domain.Token;
import com.paulstna.springsecurityapp.jwt.domain.TokenType;
import com.paulstna.springsecurityapp.user.domain.UserEntity;

import java.util.Optional;
import java.util.Set;

public interface ITokenService {
    Token save(Token token);

    Optional<Token> findByJwtToken(String token);

    void delete(Token token);

    void deleteAll(Set<Token> tokens);

    void deleteByUserAndUserAgent(UserEntity userEntity, String userAgent);

    Token buildToken(UserEntity userEntity, String jwtToken, String userAgent, String ip, TokenType tokenType);

    Token buildToken(String jwtToken, String userAgent, String ip, TokenType tokenType);

}
