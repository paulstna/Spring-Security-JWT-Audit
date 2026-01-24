package com.paulstna.springsecurityapp.auth.service;

import com.paulstna.springsecurityapp.auth.dto.AuthInternalResponseDto;
import com.paulstna.springsecurityapp.auth.domain.LoginRequest;
import com.paulstna.springsecurityapp.auth.domain.RegisterRequest;
import com.paulstna.springsecurityapp.exception.*;
import com.paulstna.springsecurityapp.jwt.domain.TokenType;
import com.paulstna.springsecurityapp.jwt.service.IJwtProvider;
import com.paulstna.springsecurityapp.user.domain.UserEntity;
import com.paulstna.springsecurityapp.jwt.domain.Token;
import com.paulstna.springsecurityapp.jwt.service.ITokenService;
import com.paulstna.springsecurityapp.user.service.IUserEntityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;


@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements IAuthService {

    private final IUserEntityService userEntityService;
    private final IJwtProvider jwtProvider;
    private final ITokenService tokenService;
    private final AuthenticationManager authenticationManager;

    @Override
    @Transactional
    public AuthInternalResponseDto register(RegisterRequest registerRequest, String userAgent, String ip) {
        UserEntity userEntity = userEntityService.buildUserEntityFromRequest(registerRequest);

        AuthInternalResponseDto authInternalResponseDto = issueTokens(userEntity);

        Token token = tokenService.buildToken(userEntity, authInternalResponseDto.getRefreshToken(), userAgent, ip , TokenType.REFRESH_TOKEN);
        userEntity.addToken(token);
        userEntityService.save(userEntity);

        return authInternalResponseDto;
    }

    @Override
    public AuthInternalResponseDto login(LoginRequest loginRequest, String userAgent, String ip) {
        Authentication authentication =  authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(), loginRequest.getPassword()
                ));

        UserEntity userEntity = userEntityService.findByUsername(loginRequest.getUsername())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User with the username " + loginRequest.getUsername() + " not found"));

        tokenService.deleteByUserAndUserAgent(userEntity, userAgent);

        AuthInternalResponseDto authInternalResponseDto = issueTokens(userEntity);

        Token token = tokenService.buildToken(
                userEntity,
                authInternalResponseDto.getRefreshToken(),
                userAgent, ip ,
                TokenType.REFRESH_TOKEN);
        tokenService.save(token);
        return authInternalResponseDto;
    }


    @Override
    @Transactional
    public AuthInternalResponseDto refreshToken(String refreshToken, String userAgent, String ip) {
        if (!StringUtils.hasText(refreshToken)) {
            throw new TokenRequiredException("Refresh token is required");
        }

        if (!jwtProvider.isJwtValid(refreshToken)) {
            throw new InvalidTokenException("Invalid refresh token");
        }

        String username = jwtProvider.extractUsername(refreshToken);
        if (username == null) {
            throw new InvalidTokenException("Invalid refresh token");
        }

        Token dbToken = tokenService.findByJwtToken(refreshToken)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        UserEntity userEntity = dbToken.getUser();

        if (dbToken.isRevoked()) {
            throw new InvalidTokenException("Invalid refresh token");
        }

        if (!dbToken.getUser().getUsername().equals(username) ||
                !dbToken.getUserAgent().equals(userAgent)) {
            throw new InvalidTokenException("Refresh token does not belong to user");
        }

        if (!dbToken.getIpAddress().equals(ip)) {
            log.warn("Refresh token IP changed for user {}. Old IP: {}, New IP: {}",
                    username, dbToken.getIpAddress(), ip);
        }

        tokenService.delete(dbToken);

        AuthInternalResponseDto authInternalResponseDto = issueTokens(userEntity);

        Token newToken = tokenService.buildToken(
                userEntity,
                authInternalResponseDto.getRefreshToken(),
                userAgent, ip ,
                TokenType.REFRESH_TOKEN);
        tokenService.save(newToken);

        return authInternalResponseDto;
    }

    @Override
    public void logout(String refreshToken) {
        if (!StringUtils.hasText(refreshToken)) {
            return;
        }

        tokenService.findByJwtToken(refreshToken)
                .ifPresent(tokenService::delete);
    }

    private AuthInternalResponseDto issueTokens(UserEntity userEntity) {
        String accessToken = jwtProvider.buildAccessJwt(
                userEntity.getUsername(),
                userEntity.getRoles()
        );
        String refreshToken = jwtProvider.buildRefreshJwt(
                userEntity.getUsername()
        );
        return new AuthInternalResponseDto(accessToken, refreshToken);
    }

}
