package com.paulstna.springsecurityapp.jwt.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("TokenHasher")
class TokenHasherTest {

    private static final String TOKEN = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhbGljZSJ9.signature";

    @Test
    @DisplayName("produces a 64-character lowercase hex digest")
    void producesHexDigest() {
        assertThat(TokenHasher.hash(TOKEN))
                .hasSize(64)
                .matches("[0-9a-f]{64}");
    }

    @Test
    @DisplayName("is deterministic, which is what makes the database lookup possible")
    void isDeterministic() {
        assertThat(TokenHasher.hash(TOKEN)).isEqualTo(TokenHasher.hash(TOKEN));
    }

    @Test
    @DisplayName("never returns the token it was given")
    void neverEchoesTheInput() {
        assertThat(TokenHasher.hash(TOKEN)).isNotEqualTo(TOKEN).doesNotContain(".");
    }

    @Test
    @DisplayName("different tokens hash differently, including a one-character difference")
    void differentInputsDifferentDigests() {
        assertThat(TokenHasher.hash(TOKEN)).isNotEqualTo(TokenHasher.hash(TOKEN + "x"));
        assertThat(TokenHasher.hash("a")).isNotEqualTo(TokenHasher.hash("b"));
    }

    @Test
    @DisplayName("matches the known SHA-256 vector for the empty string")
    void matchesKnownVector() {
        assertThat(TokenHasher.hash(""))
                .isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    @Test
    @DisplayName("rejects a null token rather than storing a bogus digest")
    void rejectsNull() {
        assertThatThrownBy(() -> TokenHasher.hash(null)).isInstanceOf(NullPointerException.class);
    }
}
