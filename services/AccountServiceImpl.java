package com.ia.iatt.security.services;

import com.ia.iatt.security.entities.AppRole;
import com.ia.iatt.security.entities.AppUser;
import com.ia.iatt.security.repositories.AppRoleRepository;
import com.ia.iatt.security.repositories.AppUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;
@Service
@Transactional
public class AccountServiceImpl implements IAccountService {
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    private AppUserRepository _appUserRepository;
    @Autowired
    private AppRoleRepository _appRoleRepository ;
    @Override
    public AppUser addNewUser(AppUser appUser) {
        String pw = appUser.getPassword();
        appUser.setPassword(bCryptPasswordEncoder.encode(pw));
        return   _appUserRepository.save(appUser);

    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return _appRoleRepository.save(appRole);
    }

    @Override
    public void addRoleToUser(String userName, String roleName) {
        AppUser appUser = _appUserRepository.findByUserName(userName);
        appUser.getAppRoles().add(_appRoleRepository.findByRoleName(roleName));
    }

    @Override
    public AppUser loadUserByUserName(String userName) {

        return _appUserRepository.findByUserName(userName);
    }

    @Override
    public List<AppUser> users() {

     return    _appUserRepository.findAll();
    }
}
