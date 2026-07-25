package com.paulstna.springsecurityapp.jwt.util;

import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Hashes refresh tokens before they are stored.
 * <p>
 * Only the hash is persisted, so a database dump alone cannot be replayed
 * against {@code /auth/refresh} — the raw token exists solely in the
 * {@code HttpOnly} cookie held by the client.
 * <p>
 * SHA-256 rather than BCrypt: a signed JWT is already high-entropy, so there is
 * nothing to brute force, and a plain digest keeps the lookup a single indexed
 * equality match instead of a scan over every stored row.
 */
@UtilityClass
public class TokenHasher {

    private static final String ALGORITHM = "SHA-256";

    public String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance(ALGORITHM)
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(ALGORITHM + " is not available", e);
        }
    }
}
