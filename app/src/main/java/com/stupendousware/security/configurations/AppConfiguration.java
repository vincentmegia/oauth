package com.stupendousware.security.configurations;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericToStringSerializer;

@Configuration()
public class AppConfiguration {
    @Value("${spring.application.name}")
    private String name;
    @Value("${spring.security.private-key-file}")
    private String privateKeyFile;
    @Value("${spring.security.public-key-file}")
    private String publicKeyFile;
    @Value("${spring.redis.host}")
    private String host;
    @Value("${spring.redis.port}")
    private int port;
    private RedisTemplate<String, Object> redisTemplate;

    @Bean
    public JedisConnectionFactory jedisConnectionFactory() {
        var jedisConnectionFactory = new JedisConnectionFactory(new RedisStandaloneConfiguration(this.host, this.port));
        return jedisConnectionFactory;
    }

    @Bean
    public RedisTemplate<String, Object> redisTemplate() {
        this.redisTemplate = new RedisTemplate<>();
        this.redisTemplate.setConnectionFactory(jedisConnectionFactory());
        this.redisTemplate.setValueSerializer(new GenericToStringSerializer<Object>(Object.class));
        return this.redisTemplate;
    }

    public String getName() {
        return name;
    }

    public String getPrivateKeyFile() {
        return privateKeyFile;
    }

    public String getPublicKeyFile() {
        return publicKeyFile;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setPrivateKeyFile(String privateKeyFile) {
        this.privateKeyFile = privateKeyFile;
    }

    public void setPublicKeyFile(String publicKeyFile) {
        this.publicKeyFile = publicKeyFile;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

}
