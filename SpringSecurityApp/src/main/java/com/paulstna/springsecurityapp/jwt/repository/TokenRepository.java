package com.paulstna.springsecurityapp.jwt.repository;

import com.paulstna.springsecurityapp.jwt.domain.Token;
import com.paulstna.springsecurityapp.user.domain.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface TokenRepository extends JpaRepository<Token, UUID> {
    Optional<Token> findByTokenHash(String tokenHash);

    void deleteByUserAndUserAgent(UserEntity userEntity, String userAgent);
}
