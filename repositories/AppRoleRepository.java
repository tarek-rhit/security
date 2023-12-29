package com.ia.iatt.security.repositories;

import com.ia.iatt.base.repository.BaseRepository;
import com.ia.iatt.security.entities.AppRole;
import org.springframework.stereotype.Repository;

@Repository
public interface AppRoleRepository extends BaseRepository<AppRole,Long> {
    AppRole findByRoleName(String roleName);
}
