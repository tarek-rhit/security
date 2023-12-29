package com.ia.iatt.security.entities;

import com.ia.iatt.base.entity.BaseEntity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AppRole extends BaseEntity<Long> {
    private String roleName ;
}
