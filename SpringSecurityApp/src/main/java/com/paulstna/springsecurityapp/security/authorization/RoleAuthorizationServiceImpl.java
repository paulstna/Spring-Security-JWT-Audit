package com.paulstna.springsecurityapp.security.authorization;

import com.paulstna.springsecurityapp.user.domain.RoleName;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class RoleAuthorizationServiceImpl implements IRoleAuthorizationService {

    private final RoleHierarchy roleHierarchy;

    @Override
    public void ensureCallerCanGrant(RoleName requested) {
        if (requested == RoleName.ROLE_SYSTEM) {
            throw new AccessDeniedException(
                    "ROLE_SYSTEM is reserved for auditing and cannot be granted through the API");
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AccessDeniedException("Cannot assign roles without an authenticated caller");
        }

        boolean callerHoldsRole = roleHierarchy
                .getReachableGrantedAuthorities(authentication.getAuthorities())
                .stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(requested.name()::equals);

        if (!callerHoldsRole) {
            throw new AccessDeniedException("Cannot grant a role you do not hold: " + requested.name());
        }
    }
}
