package com.rojojun.ajaxsecurity.domain.entity;

import jakarta.persistence.*;
import lombok.*;

import javax.management.relation.Role;
import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

@Entity
@Data
public class Account {
    @Id
    @GeneratedValue
    private Long id;
    private String username;
    private String password;
    private String email;
    private String age;
    private String role;
}
