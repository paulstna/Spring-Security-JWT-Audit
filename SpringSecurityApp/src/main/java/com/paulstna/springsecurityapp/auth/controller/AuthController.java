package com.paulstna.springsecurityapp.auth.controller;

import com.paulstna.springsecurityapp.auth.dto.AuthInternalResponseDto;
import com.paulstna.springsecurityapp.auth.domain.AuthResponse;
import com.paulstna.springsecurityapp.auth.domain.LoginRequest;
import com.paulstna.springsecurityapp.auth.domain.RegisterRequest;
import com.paulstna.springsecurityapp.auth.service.IAuthService;
import com.paulstna.springsecurityapp.common.web.ClientIpResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@RequiredArgsConstructor
@RequestMapping(value = "/api/{version}/auth")
public class AuthController {

    private final IAuthService authService;
    private final ClientIpResolver clientIpResolver;

    @Value("${app.cookie.secure:true}")
    private boolean cookieSecure;

    @Value("${jwt.refresh-token.expiration}")
    private long refreshExpirationSeconds;

    @PostMapping(path = "/register", version = "v1")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest registerRequest,
            HttpServletRequest httpRequest) {
        AuthInternalResponseDto authInternalResponseDto =
                authService.register(
                        registerRequest,
                        httpRequest.getHeader("User-Agent"),
                        clientIpResolver.resolve(httpRequest)
                );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .header(HttpHeaders.SET_COOKIE,
                        createRefreshTokenCookie(
                                authInternalResponseDto.getRefreshToken()
                        ).toString()
                )
                .body(new AuthResponse(authInternalResponseDto.getAuthToken()));
    }

    @PostMapping(path = "/login", version = "v1")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest loginRequest,
            HttpServletRequest httpRequest) {

        AuthInternalResponseDto authInternalResponseDto =
                authService.login(
                        loginRequest,
                        httpRequest.getHeader("User-Agent"),
                        clientIpResolver.resolve(httpRequest)
                );

        return ResponseEntity
                .status(HttpStatus.OK)
                .header(HttpHeaders.SET_COOKIE,
                        createRefreshTokenCookie(
                                authInternalResponseDto.getRefreshToken()
                        ).toString()
                )
                .body(new AuthResponse(authInternalResponseDto.getAuthToken()));
    }

    @PostMapping(path = "/refresh", version = "v1")
    public ResponseEntity<AuthResponse> refreshToken(
            @CookieValue(name = "refreshToken", required = false)
            String refreshToken, HttpServletRequest httpRequest
    ) {
        AuthInternalResponseDto authInternalResponseDto = authService.refreshToken(
                refreshToken,
                httpRequest.getHeader("User-Agent"),
                clientIpResolver.resolve(httpRequest)
        );

        return ResponseEntity
                .status(HttpStatus.OK)
                .header(HttpHeaders.SET_COOKIE,
                        createRefreshTokenCookie(
                                authInternalResponseDto.getRefreshToken()
                        ).toString()
                )
                .body(new AuthResponse(authInternalResponseDto.getAuthToken()));
    }

    @PostMapping(path = "/logout", version = "v1")
    public ResponseEntity<Void> logout(
            @CookieValue(name = "refreshToken", required = false) String refreshToken) {
        authService.logout(refreshToken);

        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, deleteRefreshTokenCookie().toString())
                .build();
    }

    private ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Strict")
                .path("/api/v1/auth")
                .maxAge(Duration.ofSeconds(refreshExpirationSeconds))
                .build();
    }

    private ResponseCookie deleteRefreshTokenCookie() {
        return ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Strict")
                .path("/api/v1/auth")
                .maxAge(0)
                .build();
    }
}
