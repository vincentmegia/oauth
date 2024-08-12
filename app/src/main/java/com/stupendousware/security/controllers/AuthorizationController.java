package com.stupendousware.security.controllers;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.stupendousware.security.configurations.AppConfiguration;
import com.stupendousware.security.models.AccessToken;
import com.stupendousware.security.models.AuthorizationGrant;
import com.stupendousware.security.services.JwtService;

/*
Authorization Server 
*/
@RestController
@RequestMapping(path = "${spring.application.apiPrefix}/authorization")
public class AuthorizationController {
    private JwtService jwtService;
    private AppConfiguration appConfiguration;

    public AuthorizationController(JwtService jwtService, AppConfiguration appConfiguration) {
        this.jwtService = jwtService;
        this.appConfiguration = appConfiguration;
    }

    /**
     * @param grant
     */
    @PostMapping("grant")
    public AccessToken request(@RequestBody AuthorizationGrant grant) {
        System.out.println("app name: " + appConfiguration.toString());
        try {
            var token = this.jwtService.grantEncryptedToken(grant.getUser(), appConfiguration.getPublicKeyFile());
            return new AccessToken(token);
        } catch (Exception e) {
            return new AccessToken("");
        }
    }
}
