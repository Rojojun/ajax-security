package com.rojojun.ajaxsecurity.security.configs;

import com.rojojun.ajaxsecurity.security.filter.AjaxLoginProcessingFilter;
import org.aspectj.weaver.loadtime.Aj;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@Order(0)
public class AjaxSecurityConfig {
    protected void configure(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**")
                .authorizeHttpRequests(httpRequest -> httpRequest
                        .anyRequest().authenticated()
                )
                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .csrf(csrf -> csrf
                        .disable())
        ;
    }

    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() {
        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManagerBean());
        return ajaxLoginProcessingFilter;
    }
}
