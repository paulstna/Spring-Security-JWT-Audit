package com.paulstna.springsecurityapp.jwt.service;

import com.paulstna.springsecurityapp.jwt.config.JwtConfiguration;
import com.paulstna.springsecurityapp.jwt.domain.TokenType;
import com.paulstna.springsecurityapp.user.domain.Role;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtProviderImpl implements IJwtProvider {

    private final JwtConfiguration jwtConfiguration;

    @Override
    public String buildAccessJwt(String username, Set<Role> roles) {
        return Jwts.builder()
                .subject(username)
                .claim("roles", roles.stream().map(role -> role.getRoleName().name()).toList())
                .claim("token_type", TokenType.ACCESS_TOKEN.name())
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now()
                        .plusSeconds(jwtConfiguration.getAuthTimeExpiration())))
                .signWith(jwtConfiguration.getKey())
                .compact();
    }

    @Override
    public String buildRefreshJwt(String username) {
        return Jwts.builder()
                .subject(username)
                .id(UUID.randomUUID().toString())
                .claim("token_type", TokenType.REFRESH_TOKEN.name())
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now()
                        .plusSeconds(jwtConfiguration.getRefreshTimeExpiration())))
                .signWith(jwtConfiguration.getKey())
                .compact();
    }

    @Override
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    public boolean isJwtValid(String token) {
        try {
            Jwts.parser().verifyWith(jwtConfiguration.getKey()).build().parseSignedClaims(token);
            return true;
        } catch (SignatureException e) {
            log.info("Invalid JWT signature.");
            log.trace("Invalid JWT signature trace: {}", e);
        } catch (MalformedJwtException e) {
            log.info("Invalid JWT token.");
            log.trace("Invalid JWT token trace: {}", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token.");
            log.trace("Expired JWT token trace: {}", e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token.");
            log.trace("Unsupported JWT token trace: {}", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT token compact of handler are invalid.");
            log.trace("JWT token compact of handler are invalid trace: {}", e);
        }
        return false;
    }

    @Override
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(Date.from(Instant.now()));
    }

    @Override
    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(jwtConfiguration.getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private <T> T extractClaim(String token, Function<Claims, T> resolver) {
        return resolver.apply(extractAllClaims(token));
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

}
