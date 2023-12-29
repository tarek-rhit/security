package com.ia.iatt.security.services;

import com.ia.iatt.security.entities.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    @Lazy
    private IAccountService _iAccountService ;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = _iAccountService.loadUserByUserName(username);
        Collection<GrantedAuthority> authorities = new ArrayList<>() ;
        appUser.getAppRoles().stream().forEach(
                r->{
                    authorities.add(new SimpleGrantedAuthority(r.getRoleName()));

                }
        );

        return new User(appUser.getUserName(),appUser.getPassword(),authorities);
    }


}
