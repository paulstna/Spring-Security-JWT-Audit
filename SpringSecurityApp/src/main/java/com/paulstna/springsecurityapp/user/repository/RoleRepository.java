package com.paulstna.springsecurityapp.user.repository;

import com.paulstna.springsecurityapp.user.domain.Role;
import com.paulstna.springsecurityapp.user.domain.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByRoleName(RoleName role);
}
