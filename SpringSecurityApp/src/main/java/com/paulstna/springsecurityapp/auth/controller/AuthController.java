package com.paulstna.springsecurityapp.auth.controller;

import com.paulstna.springsecurityapp.auth.dto.AuthInternalResponseDto;
import com.paulstna.springsecurityapp.auth.domain.AuthResponse;
import com.paulstna.springsecurityapp.auth.domain.LoginRequest;
import com.paulstna.springsecurityapp.auth.domain.RegisterRequest;
import com.paulstna.springsecurityapp.auth.service.IAuthService;
import com.paulstna.springsecurityapp.common.config.OpenApiConfig;
import com.paulstna.springsecurityapp.common.web.ClientIpResolver;
import com.paulstna.springsecurityapp.exception.dto.ErrorResponseDTO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@RequiredArgsConstructor
@RequestMapping(value = "/api/{version}/auth", produces = MediaType.APPLICATION_JSON_VALUE)
@Tag(name = "Authentication",
        description = "Obtaining, rotating and revoking tokens. The access token is returned in "
                + "the body; the refresh token is set as an HttpOnly cookie scoped to "
                + "/api/v1/auth and is rotated on every refresh.")
public class AuthController {

    private static final String SET_COOKIE_DESCRIPTION =
            "Refresh token, HttpOnly, SameSite=Strict, scoped to /api/v1/auth.";

    private final IAuthService authService;
    private final ClientIpResolver clientIpResolver;

    @Value("${app.cookie.secure:true}")
    private boolean cookieSecure;

    @Value("${jwt.refresh-token.expiration}")
    private long refreshExpirationSeconds;

    @Operation(summary = "Register a new account",
            description = "Creates an account with the USER role and logs it in, so the caller "
                    + "gets a usable session straight away. The username must be free.")
    @ApiResponse(responseCode = "201", description = "Account created and signed in.",
            headers = @Header(name = HttpHeaders.SET_COOKIE, description = SET_COOKIE_DESCRIPTION,
                    schema = @Schema(type = "string")))
    @ApiResponse(responseCode = "400", description = "The username or password breaks a rule.",
            content = @Content(schema = @Schema(implementation = ErrorResponseDTO.class)))
    @ApiResponse(responseCode = "409", description = "That username is already taken.",
            content = @Content(schema = @Schema(implementation = ErrorResponseDTO.class)))
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

    @Operation(summary = "Sign in",
            description = "Demo accounts: admin, manager and user, all with password Demo1234!. "
                    + "Any failure answers the same 401 so accounts cannot be enumerated; the "
                    + "real reason is recorded in the security log.")
    @ApiResponse(responseCode = "200", description = "Signed in.",
            headers = @Header(name = HttpHeaders.SET_COOKIE, description = SET_COOKIE_DESCRIPTION,
                    schema = @Schema(type = "string")))
    @ApiResponse(responseCode = "400", description = "Username or password missing.",
            content = @Content(schema = @Schema(implementation = ErrorResponseDTO.class)))
    @ApiResponse(responseCode = "401",
            description = "Wrong credentials, unknown user, or a disabled or locked account.",
            content = @Content(schema = @Schema(implementation = ErrorResponseDTO.class)))
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

    @Operation(summary = "Exchange the refresh cookie for a new access token",
            description = "Rotates the refresh token: the old one is revoked and a new cookie is "
                    + "issued, so a stolen token is usable at most once. The token is bound to "
                    + "the User-Agent that obtained it and is rejected from any other client.",
            security = @SecurityRequirement(name = OpenApiConfig.REFRESH_COOKIE_SCHEME))
    @ApiResponse(responseCode = "200", description = "New access token, refresh token rotated.",
            headers = @Header(name = HttpHeaders.SET_COOKIE, description = SET_COOKIE_DESCRIPTION,
                    schema = @Schema(type = "string")))
    @ApiResponse(responseCode = "401",
            description = "Cookie missing, malformed, expired, already rotated, or presented by "
                    + "a different client. An access token is not accepted here.",
            content = @Content(schema = @Schema(implementation = ErrorResponseDTO.class)))
    @PostMapping(path = "/refresh", version = "v1")
    public ResponseEntity<AuthResponse> refreshToken(
            @Parameter(hidden = true)
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

    @Operation(summary = "Sign out",
            description = "Revokes the refresh token server side and clears the cookie. Already "
                    + "issued access tokens stay valid until they expire, which is why they are "
                    + "short lived. Signing out twice is not an error.",
            security = @SecurityRequirement(name = OpenApiConfig.REFRESH_COOKIE_SCHEME))
    @ApiResponse(responseCode = "204", description = "Session revoked and cookie cleared.",
            headers = @Header(name = HttpHeaders.SET_COOKIE,
                    description = "Same cookie with Max-Age=0, which deletes it.",
                    schema = @Schema(type = "string")))
    @PostMapping(path = "/logout", version = "v1")
    public ResponseEntity<Void> logout(
            @Parameter(hidden = true)
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
