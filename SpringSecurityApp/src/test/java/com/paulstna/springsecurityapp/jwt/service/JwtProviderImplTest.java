package com.paulstna.springsecurityapp.jwt.service;

import com.paulstna.springsecurityapp.jwt.config.JwtConfiguration;
import com.paulstna.springsecurityapp.jwt.domain.TokenType;
import com.paulstna.springsecurityapp.user.domain.Role;
import com.paulstna.springsecurityapp.user.domain.RoleName;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JwtProviderImpl")
class JwtProviderImplTest {

    private static final String SECRET = Base64.getEncoder()
            .encodeToString("unit-test-secret-key-long-enough-for-hmac-sha-512-abcdefghijklmnop".getBytes());
    private static final String OTHER_SECRET = Base64.getEncoder()
            .encodeToString("a-completely-different-key-also-long-enough-for-hs512-qrstuvwxyz00".getBytes());

    private JwtProviderImpl provider;

    @BeforeEach
    void setUp() {
        provider = providerWith(SECRET, 900L, 1_296_000L);
    }

    private JwtProviderImpl providerWith(String secret, long accessTtl, long refreshTtl) {
        JwtConfiguration configuration = new JwtConfiguration();
        ReflectionTestUtils.setField(configuration, "secret", secret);
        ReflectionTestUtils.setField(configuration, "authTimeExpiration", accessTtl);
        ReflectionTestUtils.setField(configuration, "refreshTimeExpiration", refreshTtl);
        configuration.init();
        return new JwtProviderImpl(configuration);
    }

    private Set<Role> roles(RoleName... names) {
        return java.util.Arrays.stream(names)
                .map(name -> new Role(null, name))
                .collect(java.util.stream.Collectors.toSet());
    }

    @Test
    @DisplayName("an access token carries the subject and the caller's roles")
    void accessTokenCarriesSubjectAndRoles() {
        String token = provider.buildAccessJwt("alice", roles(RoleName.ROLE_ADMIN));

        assertThat(provider.extractUsername(token)).isEqualTo("alice");
        assertThat(provider.extractAllClaims(token).get("roles", List.class))
                .containsExactly("ROLE_ADMIN");
    }

    @Test
    @DisplayName("tokens declare their type, which is what stops one standing in for the other")
    void tokensDeclareTheirType() {
        assertThat(provider.extractTokenType(provider.buildAccessJwt("alice", roles(RoleName.ROLE_USER))))
                .isEqualTo(TokenType.ACCESS_TOKEN);
        assertThat(provider.extractTokenType(provider.buildRefreshJwt("alice")))
                .isEqualTo(TokenType.REFRESH_TOKEN);
    }

    @Test
    @DisplayName("a refresh token carries no roles, so it cannot convey authority")
    void refreshTokenCarriesNoRoles() {
        String refresh = provider.buildRefreshJwt("alice");

        assertThat(provider.extractAllClaims(refresh).get("roles")).isNull();
        assertThat(provider.extractUsername(refresh)).isEqualTo("alice");
    }

    @Test
    @DisplayName("each refresh token is unique even for the same user at the same moment")
    void refreshTokensAreUnique() {
        assertThat(provider.buildRefreshJwt("alice"))
                .as("a shared jti would make rotation collide")
                .isNotEqualTo(provider.buildRefreshJwt("alice"));
    }

    @Test
    @DisplayName("a token signed with our key validates")
    void ownTokensAreValid() {
        assertThat(provider.isJwtValid(provider.buildAccessJwt("alice", roles(RoleName.ROLE_USER)))).isTrue();
    }

    @Test
    @DisplayName("a token signed with someone else's key is rejected")
    void foreignSignatureIsRejected() {
        String forged = providerWith(OTHER_SECRET, 900L, 900L)
                .buildAccessJwt("alice", roles(RoleName.ROLE_ADMIN));

        assertThat(provider.isJwtValid(forged)).isFalse();
    }

    @Test
    @DisplayName("an expired token is rejected")
    void expiredTokenIsRejected() {
        JwtProviderImpl expiring = providerWith(SECRET, -60L, -60L);
        String stale = expiring.buildAccessJwt("alice", roles(RoleName.ROLE_USER));

        assertThat(provider.isJwtValid(stale)).isFalse();
    }

    @Test
    @DisplayName("garbage is rejected without throwing")
    void malformedTokensAreRejectedQuietly() {
        assertThat(provider.isJwtValid("not-a-jwt")).isFalse();
        assertThat(provider.isJwtValid("a.b.c")).isFalse();
        assertThat(provider.isJwtValid("")).isFalse();
    }

    @Test
    @DisplayName("a tampered payload invalidates the signature")
    void tamperedPayloadIsRejected() {
        String[] parts = provider.buildAccessJwt("alice", roles(RoleName.ROLE_USER)).split("\\.");
        String escalated = Base64.getUrlEncoder().withoutPadding().encodeToString(
                new String(Base64.getUrlDecoder().decode(parts[1]))
                        .replace("ROLE_USER", "ROLE_ADMIN").getBytes());

        assertThat(provider.isJwtValid(parts[0] + "." + escalated + "." + parts[2])).isFalse();
    }

    @Test
    @DisplayName("isTokenExpired reflects the configured lifetime")
    void expiryIsDrivenByConfiguration() {
        assertThat(provider.isTokenExpired(provider.buildAccessJwt("alice", roles(RoleName.ROLE_USER))))
                .isFalse();
        assertThat(providerWith(SECRET, -1L, -1L).isTokenExpired(
                providerWith(SECRET, -1L, -1L).buildRefreshJwt("alice")))
                .isTrue();
    }
}
