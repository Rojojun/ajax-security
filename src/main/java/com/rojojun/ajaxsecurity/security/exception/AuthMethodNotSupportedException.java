package com.rojojun.ajaxsecurity.security.exception;

import org.springframework.security.authentication.AuthenticationServiceException;

public class AuthMethodNotSupportedException extends AuthenticationServiceException {
    private static final long serialVersionUID = 370504308301304496L;

    public AuthMethodNotSupportedException(String msg) {
        super(msg);
    }
}
