package com.rojojun.ajaxsecurity.security.service;

import com.rojojun.ajaxsecurity.domain.entity.Account;
import lombok.Data;
import lombok.Getter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.List;
import java.util.stream.Collectors;

@Getter
public class UserDetail extends User {
    private Account account;
    private List<String> roles;

    public UserDetail(Account account, List<String> roles) {
        super(account.getUsername(), account.getPassword(), roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
        this.account = account;
        this.roles = roles;
    }
}
