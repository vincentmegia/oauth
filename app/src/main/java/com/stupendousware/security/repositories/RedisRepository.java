package com.stupendousware.security.repositories;

import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import jakarta.annotation.PostConstruct;

@Repository
public class RedisRepository {
    private Logger logger = Logger.getLogger(RedisRepository.class.getName());
    private RedisTemplate<String, Object> redisTemplate;
    private HashOperations hashOperations;

    public RedisRepository(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * 
     */
    @PostConstruct
    public void postInit() {
        this.hashOperations = redisTemplate.opsForHash();
    }

    public void set(Map<String, String> map) {
        this.logger.info("writing to redis");
        this.hashOperations.put("test-user-hash", "test-user-key", map);
        this.redisTemplate.expire("test-user-hash", 60, TimeUnit.SECONDS);
        this.logger.info("writing to redis completed: " + map);
    }
}
