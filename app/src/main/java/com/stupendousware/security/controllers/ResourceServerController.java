package com.stupendousware.security.controllers;

import com.stupendousware.security.models.AccessToken;
import com.stupendousware.security.models.ProtectedResource;

public class ResourceServerController {
    /**
     * Based on token provides accessible resource
     * 
     * @param code
     * @return
     */
    public ProtectedResource request(AccessToken token) {
        return new ProtectedResource();
    }
}
