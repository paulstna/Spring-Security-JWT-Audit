package com.paulstna.springsecurityapp.audit.model;

import com.paulstna.springsecurityapp.security.SecurityUser;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;
import java.util.UUID;

@RequiredArgsConstructor
public class SpringSecurityAuditorAware implements AuditorAware<UUID> {

    private final SystemAuditorProvider systemAuditorProvider;

    @Override
    public Optional<UUID> getCurrentAuditor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.isAuthenticated()
                && auth.getPrincipal() instanceof SecurityUser user) {
            return Optional.of(user.getId());
        }

        return Optional.of(systemAuditorProvider.getSystemId());
    }
}

