package com.stupendousware.security.controllers;

import com.stupendousware.security.models.AuthorizationGrant;
import com.stupendousware.security.models.AuthorizationRequest;
import com.stupendousware.security.models.Grant;

/*
Resource owner provides request grant
*/
public class ResourceController {

    /**
     * @param request
     * @return
     */
    public Grant request(AuthorizationRequest request) {
        return new AuthorizationGrant();
    }
}
