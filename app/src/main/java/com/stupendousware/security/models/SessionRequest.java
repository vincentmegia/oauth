package com.stupendousware.security.models;

public class SessionRequest {
    private String userId;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    @Override
    public String toString() {
        return "SessionRequest [userId=" + userId + "]";
    }
}
