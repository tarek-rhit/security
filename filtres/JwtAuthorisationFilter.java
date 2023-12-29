package com.ia.iatt.security.filtres;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.ia.iatt.security.utils.JwtTokenProvider;
import com.ia.iatt.security.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

public class JwtAuthorisationFilter extends OncePerRequestFilter {
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if(request.getServletPath().equals("/refreshToken")){
            filterChain.doFilter(request,response);
        }
        else {
            String jwtAuthorisationToken = request.getHeader(JwtUtil.AUTH_HEADER);

            if (jwtAuthorisationToken != null && jwtAuthorisationToken.startsWith(JwtUtil.PREFIX)) {
                try {
                    String jwt = jwtAuthorisationToken.substring(JwtUtil.PREFIX.length());
                    System.out.println("aaaaa" + jwt);
                    Algorithm algorithm = Algorithm.HMAC256(JwtUtil.SECRET);
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();

                    DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                    String userName = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

                    Arrays.stream(roles).forEach(r->{
                        System.out.println(r);
                    });

                    Collection<GrantedAuthority> authorities = new ArrayList<>();
                    for (String r : roles) {
                        authorities.add(new SimpleGrantedAuthority(r));

                    }

                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userName, null,
                            authorities);

                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    filterChain.doFilter(request, response);
                } catch (Exception e) {
                    response.setHeader("errorMessage", e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                    System.out.println(e.getMessage());
                }
            } else {
                filterChain.doFilter(request, response);
            }
        }
    }
}
