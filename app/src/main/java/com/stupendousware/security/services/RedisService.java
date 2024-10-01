package com.stupendousware.security.services;

import java.util.Map;
import java.util.logging.Logger;

import org.springframework.stereotype.Service;

import com.stupendousware.security.repositories.RedisRepository;

@Service
public class RedisService {
    private Logger logger = Logger.getLogger(RedisService.class.getName());
    private RedisRepository redisRepository;

    public RedisService(RedisRepository redisRepository) throws Exception {
        this.redisRepository = redisRepository;
    }

    public void set(Map<String, String> map) {
        this.redisRepository.set(map);
    }
}
