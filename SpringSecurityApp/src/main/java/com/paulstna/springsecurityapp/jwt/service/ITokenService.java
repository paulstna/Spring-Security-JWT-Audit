package com.paulstna.springsecurityapp.jwt.service;

import com.paulstna.springsecurityapp.jwt.domain.Token;
import com.paulstna.springsecurityapp.jwt.domain.TokenType;
import com.paulstna.springsecurityapp.user.domain.UserEntity;

import java.util.Optional;
import java.util.Set;

public interface ITokenService {
    Token save(Token token);

    Optional<Token> findByRefreshToken(String rawRefreshToken);

    void delete(Token token);

    void deleteAll(Set<Token> tokens);

    void deleteByUserAndUserAgent(UserEntity userEntity, String userAgent);

    Token buildToken(UserEntity userEntity, String rawRefreshToken, String userAgent, String ip, TokenType tokenType);

    Token buildToken(String rawRefreshToken, String userAgent, String ip, TokenType tokenType);

}
