package com.stupendousware.security.configurations;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration()
public class AppConfiguration {
    @Value("${spring.application.name}")
    private String name;
    @Value("${spring.security.private-key-file}")
    private String privateKeyFile;
    @Value("${spring.security.public-key-file}")
    private String publicKeyFile;

    public String getName() {
        return name;
    }

    public String getPrivateKeyFile() {
        return privateKeyFile;
    }

    public String getPublicKeyFile() {
        return publicKeyFile;
    }

    @Override
    public String toString() {
        return "AppConfiguration [name=" + name + ", privateKeyFile=" + privateKeyFile + ", publicKeyFile="
                + publicKeyFile + "]";
    }
}
