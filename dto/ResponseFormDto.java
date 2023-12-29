package com.ia.iatt.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.userdetails.User;
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResponseFormDto {
    private User user ;
    private String acces_token;
    private String refresh_token ;

}
