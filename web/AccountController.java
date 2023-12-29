package com.ia.iatt.security.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ia.iatt.security.dto.RoleUserForm;
import com.ia.iatt.security.entities.AppRole;
import com.ia.iatt.security.entities.AppUser;
import com.ia.iatt.security.services.IAccountService;
import com.ia.iatt.security.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/account")
public class AccountController {
    @Autowired
    private IAccountService _iAccountService ;
    @GetMapping("/users")
    public List<AppUser>  getAllUsers (){
      return   _iAccountService.users();
    }
    @PostMapping("/addUser")
    public  AppUser saveUser (@RequestBody AppUser appUser){
        return  _iAccountService.addNewUser(appUser);
    }

    @PostMapping("/addRole")
    public  AppRole saveRole (@RequestBody AppRole appRole){
        return  _iAccountService.addNewRole(appRole);
    }
    @PostMapping(path = "addRoleToUser")
    public  void addRoleToUser(@RequestBody RoleUserForm roleUserForm){
         _iAccountService.addRoleToUser(roleUserForm.getUserName(),roleUserForm.getRoleName());
    }


    @GetMapping(path = "/refreshToken")
    public  void  refreshToken (HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authToken = request.getHeader(JwtUtil.AUTH_HEADER);
        if(authToken!=null && authToken.startsWith(JwtUtil.PREFIX)){

            try {
                String jwt = authToken.substring(JwtUtil.PREFIX.length());
                System.out.println(jwt);
                Algorithm algorithm = Algorithm.HMAC256(JwtUtil.SECRET);
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();

                DecodedJWT decodedJWT =  jwtVerifier.verify(jwt);
                String userName= decodedJWT.getSubject();


                AppUser appUser = _iAccountService.loadUserByUserName(userName);
                String jwtAccesToken = JWT.create()
                        .withSubject(appUser.getUserName())
                        .withExpiresAt(new Date(System.currentTimeMillis()+JwtUtil.EXPIRE_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",appUser.getAppRoles().stream().map(
                                r->r.getRoleName()
                        ).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String,String> idToken= new HashMap<>();
                idToken.put("acces_token",jwtAccesToken);
                idToken.put("refresh_token",jwt);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);

            }
            catch (Exception e)
            {
                throw  e ;
            }

        }
        else  {
            throw  new RuntimeException("Refresh Token Required");
        }


    }
    @GetMapping("/profile")
    public  AppUser profile(Principal principal) {
        return  _iAccountService.loadUserByUserName(principal.getName());
    }











}
