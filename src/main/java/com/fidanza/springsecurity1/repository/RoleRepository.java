package com.fidanza.springsecurity1.repository;

import com.fidanza.springsecurity1.model.Role;
import com.fidanza.springsecurity1.model.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleName roleName);
}
