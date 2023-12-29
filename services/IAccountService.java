package com.ia.iatt.security.services;

import com.ia.iatt.security.entities.AppRole;
import com.ia.iatt.security.entities.AppUser;

import java.util.List;

public interface IAccountService {
    AppUser addNewUser (AppUser appUser) ;
    AppRole addNewRole (AppRole appRole);
    void addRoleToUser(String userName, String roleName);
    AppUser loadUserByUserName(String UserName);
    List<AppUser> users () ;
}
