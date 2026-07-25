package com.paulstna.springsecurityapp.jwt.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.paulstna.springsecurityapp.audit.model.Auditable;
import com.paulstna.springsecurityapp.user.domain.UserEntity;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "tokens")
@Builder
@Getter
@Setter
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@AllArgsConstructor
public class Token extends Auditable {

    /** SHA-256 of the refresh token — never the token itself. */
    @Column(length = 64, unique = true, nullable = false)
    private String tokenHash;

    @Enumerated(EnumType.STRING)
    private TokenType tokenType = TokenType.REFRESH_TOKEN;
    private boolean revoked = false;

    @Column(nullable = false)
    private String userAgent;

    @Column(nullable = false)
    private String ipAddress;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    @JsonIgnore
    private UserEntity user;

}
