package com.ia.iatt.security.repositories;

import com.ia.iatt.base.repository.BaseRepository;
import com.ia.iatt.security.entities.AppUser;
import org.springframework.stereotype.Repository;

@Repository
public interface AppUserRepository extends BaseRepository<AppUser,Long> {
    AppUser findByUserName(String userNAme);
}
