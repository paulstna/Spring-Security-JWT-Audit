package com.paulstna.springsecurityapp.jwt.service;

import com.paulstna.springsecurityapp.jwt.domain.Token;
import com.paulstna.springsecurityapp.jwt.domain.TokenType;
import com.paulstna.springsecurityapp.jwt.repository.TokenRepository;
import com.paulstna.springsecurityapp.jwt.util.TokenHasher;
import com.paulstna.springsecurityapp.user.domain.UserEntity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements ITokenService {

    private final TokenRepository tokenRepository;

    @Override
    public Token save(Token token) {
        return tokenRepository.save(token);
    }

    @Override
    public Optional<Token> findByRefreshToken(String rawRefreshToken) {
        return tokenRepository.findByTokenHash(TokenHasher.hash(rawRefreshToken));
    }

    @Override
    public void delete(Token token) {
        tokenRepository.delete(token);
    }

    @Transactional
    @Override
    public void deleteAll(Set<Token> tokens) {
        tokenRepository.deleteAll(tokens);
    }

    @Transactional
    @Override
    public void deleteByUserAndUserAgent(UserEntity userEntity, String userAgent) {
        tokenRepository.deleteByUserAndUserAgent(userEntity, userAgent);
    }

    @Override
    public Token buildToken(String rawRefreshToken, String userAgent, String ip, TokenType tokenType) {
        return Token.builder()
                .tokenHash(TokenHasher.hash(rawRefreshToken))
                .userAgent(userAgent)
                .tokenType(tokenType)
                .ipAddress(ip)
                .build();
    }

    @Override
    public Token buildToken(UserEntity userEntity, String rawRefreshToken, String userAgent, String ip, TokenType tokenType) {
        Token token = buildToken(rawRefreshToken, userAgent, ip, tokenType);
        token.setUser(userEntity);
        return token;
    }

}
