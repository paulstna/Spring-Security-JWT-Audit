package com.paulstna.springsecurityapp.audit.config;

import com.paulstna.springsecurityapp.audit.model.SpringSecurityAuditorAware;
import com.paulstna.springsecurityapp.audit.model.SystemAuditorProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import java.util.UUID;

@Configuration
@EnableJpaAuditing
@RequiredArgsConstructor
public class JpaAuditingConfig {

    private final SystemAuditorProvider systemAuditorProvider;

    @Bean
    public AuditorAware<UUID> auditorProvider() {
        return new SpringSecurityAuditorAware(systemAuditorProvider);
    }
}
