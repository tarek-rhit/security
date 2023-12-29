package com.ia.iatt.security.entities;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ia.iatt.base.entity.BaseEntity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.Collection;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name="User_type",
        discriminatorType = DiscriminatorType.INTEGER)
public class AppUser extends BaseEntity<Long> {
    private String nom ;
    private String userName;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private  String password;
    @ManyToMany(fetch = FetchType.EAGER)
    private Collection<AppRole> appRoles;
}
