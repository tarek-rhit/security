package com.ia.iatt.security.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.ia.iatt.security.entities.UserPrincipal;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
@Component
public class JwtTokenProvider {
    public  String generateJwtToken(UserPrincipal userPrincipal){
        List<String> claims= getClaimsFromUser(userPrincipal);
        return JWT.create().
                withIssuer(JwtUtil.GET_ARRAYS_LLC)
                .withAudience(JwtUtil.GET_ARRAYS_Administrations)
                .withIssuedAt(new Date())
                .withSubject(userPrincipal.getUsername())
                .withClaim(JwtUtil.AUTHORITHIES,claims)
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtUtil.EXPIRE_ACCESS_TOKEN))
                .sign(Algorithm.HMAC256(JwtUtil.SECRET));
    }
    public  List<GrantedAuthority> getAthorities(String token){
        List<String> claims= getClaimsFromToken(token);
        return  claims.stream().map(c->new SimpleGrantedAuthority(c)).collect(Collectors.toList());
    }

    private List<String> getClaimsFromToken(String token) {
        JWTVerifier verifier = getJWTverifier();

        return Arrays.stream(verifier.verify(token).getClaim(JwtUtil.AUTHORITHIES).asArray(String.class)).toList();
    }

    private boolean isTokenExpired(JWTVerifier verifier, String token) {
        Date expiration = verifier.verify(token).getExpiresAt();
        return expiration.before(new Date());
    }

    public Authentication getAuthentication(String userName, List<GrantedAuthority> authorities,
                                            HttpServletRequest request) {
        UsernamePasswordAuthenticationToken usernamePasswordToken = new
                UsernamePasswordAuthenticationToken(userName,null,authorities);
        usernamePasswordToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return  usernamePasswordToken;

    }

    public  boolean isTokenValid(String userName, String token){
        JWTVerifier verifier = getJWTverifier();
        return StringUtils.isNotEmpty(userName)&& !isTokenExpired(verifier,token);
    }
    public  String getSubject(String token){
        JWTVerifier verifier = getJWTverifier();
        return verifier.verify(token).getSubject();
    }
    private JWTVerifier getJWTverifier() {
        JWTVerifier verifier ;
        try {
            Algorithm algorithm = Algorithm.HMAC256(JwtUtil.SECRET);
            verifier=JWT.require(algorithm).withIssuer(JwtUtil.GET_ARRAYS_LLC).build();

        }
        catch (JWTVerificationException exception){
            throw  new JWTVerificationException(JwtUtil.TOKEN_CANNOT_BE_VERIFEID);
        }
        return  verifier;
    }

    private List<String> getClaimsFromUser(UserPrincipal userPrincipal) {
        return  userPrincipal.getAuthorities().stream().map(ga-> ga.getAuthority()).collect(Collectors.toList());
    }
}
