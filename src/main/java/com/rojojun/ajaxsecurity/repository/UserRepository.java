package com.rojojun.ajaxsecurity.repository;

import com.rojojun.ajaxsecurity.domain.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {
    Account findByUsername(String username);
}
