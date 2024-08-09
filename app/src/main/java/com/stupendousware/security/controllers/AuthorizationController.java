package com.stupendousware.security.controllers;

import com.stupendousware.security.models.AccessToken;
import com.stupendousware.security.models.AuthorizationGrant;

/*
Authorization Server 
*/
public class AuthorizationController {
    /**
     * @param grant
     */
    public AccessToken request(AuthorizationGrant grant) {
        return new AccessToken();
    }
}
