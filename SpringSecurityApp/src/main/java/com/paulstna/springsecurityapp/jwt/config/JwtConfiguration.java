package com.paulstna.springsecurityapp.jwt.config;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;


@Getter
@Component
public class JwtConfiguration {
    @Value("${jwt.secret-key}")
    private String secret;

    @Value("${jwt.auth-token.expiration}")
    private Long authTimeExpiration;

    @Value("${jwt.refresh-token.expiration}")
    private Long refreshTimeExpiration;

    private SecretKey key;

    @PostConstruct
    public void init() {
        key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(getSecret()));
    }
}
