package com.stupendousware.security.controllers;

import java.util.HashMap;
import java.util.logging.Logger;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.stupendousware.security.configurations.AppConfiguration;
import com.stupendousware.security.models.AccessToken;
import com.stupendousware.security.models.AuthorizationGrant;
import com.stupendousware.security.models.SessionRequest;
import com.stupendousware.security.services.JwtService;
import com.stupendousware.security.services.RedisService;

/*
Authorization Server 
*/
@RestController
@RequestMapping(path = "${spring.application.apiPrefix}/authorization")
public class AuthorizationController {
    private Logger logger = Logger.getLogger(AuthorizationController.class.getName());
    private JwtService jwtService;
    private RedisService redisService;
    private AppConfiguration appConfiguration;

    public AuthorizationController(JwtService jwtService,
            AppConfiguration appConfiguration,
            RedisService redisService) {
        this.jwtService = jwtService;
        this.appConfiguration = appConfiguration;
        this.redisService = redisService;
    }

    /**
     * @param grant
     */
    @PostMapping("grant")
    public AccessToken request(@RequestBody AuthorizationGrant grant) {
        logger.info("app name: " + appConfiguration.toString());
        try {
            var token = this.jwtService.grantEncryptedToken(grant.getUser(), appConfiguration.getPublicKeyFile());
            return new AccessToken(token);
        } catch (Exception e) {
            return new AccessToken("");
        }
    }

    @PostMapping("session")
    public void createSession(@RequestBody SessionRequest sessionRequest) {
        logger.info("creatingSession for request: ");
        var map = new HashMap<String, String>();
        map.put("lastname", "megia2");
        map.put("firstname", "vince2");
        redisService.set(map);
    }
}
