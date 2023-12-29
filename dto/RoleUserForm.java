package com.ia.iatt.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RoleUserForm {
    private  String userName;
    private  String roleName ;
}
