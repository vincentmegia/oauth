package com.stupendousware.security.models;

/*
Grant is a form of acknowledgement from a resource owner
that needs to be confired by authorixation server
*/
public class AuthorizationGrant extends Grant {
    private User user;

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
