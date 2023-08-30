package com.rojojun.ajaxsecurity.security.provider;

import com.rojojun.ajaxsecurity.security.service.AccountContext;
import com.rojojun.ajaxsecurity.security.service.FormWebAuthenticationDetails;
import com.rojojun.ajaxsecurity.security.service.UserDetail;
import com.rojojun.ajaxsecurity.security.token.AjaxAuthenticationToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Component
public class AjaxAuthenticationProvider implements AuthenticationProvider {
    private UserDetailsService userDetailsService;
    private PasswordEncoder passwordEncoder;

    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String loginId = authentication.getName();
        String passwd = (String) authentication.getCredentials();

        AccountContext userDetails = (AccountContext) userDetailsService.loadUserByUsername(loginId);

        if (!passwordEncoder.matches(passwd, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid Password");
        }

        return new AjaxAuthenticationToken(userDetails.getAccount(), null, userDetails.getAuthorities());
    }

    public boolean supports(Class<?> authentication) {
        return authentication.equals(AjaxAuthenticationToken.class);
    }
}
