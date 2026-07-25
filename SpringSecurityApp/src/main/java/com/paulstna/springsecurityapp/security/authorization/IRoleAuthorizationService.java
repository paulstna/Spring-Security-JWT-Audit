package com.paulstna.springsecurityapp.security.authorization;

import com.paulstna.springsecurityapp.user.domain.RoleName;

public interface IRoleAuthorizationService {
    void ensureCallerCanGrant(RoleName requested);
}
