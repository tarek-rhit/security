package com.ia.iatt.security.filtres;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ia.iatt.security.dto.ResponseFormDto;
import com.ia.iatt.security.utils.JwtTokenProvider;
import com.ia.iatt.security.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;


public class JwtAuthenticationFiltre extends AbstractAuthenticationProcessingFilter {
    @Autowired
private JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationFiltre() {
        super(new AntPathRequestMatcher("/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
     /*  String userName= request.getParameter("userName");
       String password= request.getParameter("password");*/

        String userName, password;

        try {
            Map<String, String> requestMap = new ObjectMapper().readValue(request.getInputStream(), Map.class);
            userName = requestMap.get("userName");
            password = requestMap.get("password");
        } catch (IOException e) {
            throw new AuthenticationServiceException(e.getMessage(), e);
        }

        UsernamePasswordAuthenticationToken AuthenticationToken = new UsernamePasswordAuthenticationToken(userName,password);
      //  return  _authenticationManager.authenticate(AuthenticationToken);
        return  this.getAuthenticationManager().authenticate(AuthenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        User user = (User) authResult.getPrincipal();


        Algorithm algorithm = Algorithm.HMAC256(JwtUtil.SECRET);
        String jwtAccesToken = JWT.create()
                .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+JwtUtil.EXPIRE_ACCESS_TOKEN))
                                .withIssuer(request.getRequestURL().toString())
                                        .withClaim("roles",user.getAuthorities().stream().map(
                                                ga->ga.getAuthority()
                                        ).collect(Collectors.toList()))
                                                .sign(algorithm);

        String jwtRefreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtUtil.EXPIRE_REFRESH_TOKEN))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);

        Map<String, ResponseFormDto> userLogged= new HashMap<>();
        userLogged.put("userInformation",new ResponseFormDto(user,jwtAccesToken,jwtRefreshToken));
        response.setContentType("application/json");
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.writeValue(response.getOutputStream(),userLogged);
        return ;


    }
}
