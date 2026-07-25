package com.paulstna.springsecurityapp.security;

import com.paulstna.springsecurityapp.support.AbstractIntegrationTest;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Transactional
@DisplayName("JWT handling")
class TokenSecurityIT extends AbstractIntegrationTest {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64_DEC = Base64.getUrlDecoder();

    /**
     * Regression: the filter checked the signature and expiry but never the
     * token_type claim, so a refresh token authenticated any request and turned a
     * 15 minute session into a 15 day one, bypassing rotation entirely.
     */
    @Test
    @DisplayName("a refresh token is refused as a bearer token")
    void refreshTokenCannotBeUsedAsAccessToken() throws Exception {
        String refreshToken = refreshTokenFor(MANAGER);

        mockMvc.perform(get("/api/v1/users").header(HttpHeaders.AUTHORIZATION, bearer(refreshToken)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("an access token is refused as a refresh cookie")
    void accessTokenCannotBeUsedAsRefreshToken() throws Exception {
        String accessToken = accessTokenFor(MANAGER);

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                        .cookie(new Cookie("refreshToken", accessToken)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("a genuine access token is still accepted")
    void genuineAccessTokenWorks() throws Exception {
        mockMvc.perform(get("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(MANAGER))))
                .andExpect(status().isOk());
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"", "not-a-jwt", "a.b.c", "Bearer-without-token"})
    @DisplayName("malformed credentials never authenticate")
    void malformedTokensAreRefused(String token) throws Exception {
        mockMvc.perform(get("/api/v1/users").header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("a wrong authentication scheme is ignored")
    void nonBearerSchemeIsIgnored() throws Exception {
        mockMvc.perform(get("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, "Basic " + accessTokenFor(MANAGER)))
                .andExpect(status().isForbidden());
    }

    /**
     * A byte in the middle of the signature, not the last base64 character: the
     * final character of an 86-char signature carries only 4 meaningful bits, so
     * sixteen different characters decode to the very same 64 bytes.
     */
    @Test
    @DisplayName("flipping a signature byte invalidates the token")
    void tamperedSignatureIsRefused() throws Exception {
        String[] parts = accessTokenFor(MANAGER).split("\\.");
        byte[] signature = B64_DEC.decode(parts[2]);
        signature[10] ^= 0xFF;

        mockMvc.perform(get("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION,
                                bearer(parts[0] + "." + parts[1] + "." + B64.encodeToString(signature))))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("rewriting the roles claim without re-signing is refused")
    void tamperedPayloadIsRefused() throws Exception {
        String[] parts = accessTokenFor(USER).split("\\.");
        String escalated = B64.encodeToString(new String(B64_DEC.decode(parts[1]), StandardCharsets.UTF_8)
                .replace("\"ROLE_USER\"", "\"ROLE_ADMIN\"")
                .getBytes(StandardCharsets.UTF_8));

        mockMvc.perform(get("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(parts[0] + "." + escalated + "." + parts[2])))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("a token re-signed with an attacker's key is refused")
    void forgedSignatureIsRefused() throws Exception {
        String[] parts = accessTokenFor(USER).split("\\.");
        String escalated = B64.encodeToString(new String(B64_DEC.decode(parts[1]), StandardCharsets.UTF_8)
                .replace("\"ROLE_USER\"", "\"ROLE_ADMIN\"")
                .getBytes(StandardCharsets.UTF_8));

        String signingInput = parts[0] + "." + escalated;
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec("an-attacker-controlled-key-that-is-long-enough-for-hs512".getBytes(
                StandardCharsets.UTF_8), "HmacSHA512"));
        String forged = B64.encodeToString(mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8)));

        mockMvc.perform(get("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(signingInput + "." + forged)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("an unsigned alg=none token is refused")
    void algNoneIsRefused() throws Exception {
        String[] parts = accessTokenFor(USER).split("\\.");
        String header = B64.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));

        mockMvc.perform(get("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(header + "." + parts[1] + ".")))
                .andExpect(status().isForbidden());
    }
}
