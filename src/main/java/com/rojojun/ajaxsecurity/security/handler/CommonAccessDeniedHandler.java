package com.rojojun.ajaxsecurity.security.handler;

import com.rojojun.ajaxsecurity.security.service.UserDetail;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

public class CommonAccessDeniedHandler implements AccessDeniedHandler {
    private String errorPage;
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();


    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {

        String ajaxHandler = request.getHeader("X-Ajax-call");
        String result = "";

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setCharacterEncoding("UTF-8");

        if (ajaxHandler == null) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication.getPrincipal();
            if (principal instanceof UserDetail) {
                String username = ((((UserDetail) principal).getUsername()));
                request.setAttribute("username", username);
            }
            request.setAttribute("errormsg", accessDeniedException);
            redirectStrategy.sendRedirect(request, response, errorPage);
        } else {
            if ("true".equals(ajaxHandler)) {
                result = accessDeniedException.getMessage();
            } else {
                result = null;
            }
            response.getWriter().println(result);
            response.getWriter().flush();
        }
    }

    public void setErrorPage(String errorPage) {
        if ((errorPage != null) && !errorPage.startsWith("/")) {
            throw new IllegalArgumentException("errorPage must begin with '/'");
        }

        this.errorPage = errorPage;
    }
}
