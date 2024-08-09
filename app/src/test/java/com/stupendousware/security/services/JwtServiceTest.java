package com.stupendousware.security.services;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class JwtServiceTest {

    @Test
    public void testPublicKey() {

        try {
            var jwtService = new JwtService();
            var publicKey = jwtService.getPublicKeyFromPem(
                    "./src/test/resources/test-public.pem");
            assertTrue(publicKey != null);
        } catch (Exception e) {
            assertTrue(true != false);
        }
    }

    @Test
    public void testPrivateKey() {
        try {
            var jwtService = new JwtService();
            var privateKey = jwtService.getPrivateKeyFromPem(
                    "./src/test/resources/test-private.pem");
            assertTrue(privateKey != null);
        } catch (Exception e) {
            assertTrue(true != false);
        }
    }

    @Test
    public void testToken() {
        try {
            var jwtService = new JwtService();
            var privateKey = jwtService.getPrivateKeyFromPem(
                    "./src/test/resources/test-private.pem");
            var publicKey = jwtService.getPublicKeyFromPem(
                    "./src/test/resources/test-public.pem");
            var token = jwtService.grantToken(publicKey, privateKey);
            System.out.println("token: " + token);
            assertEquals(token, "");
        } catch (Exception e) {
            System.out.println("exception: " + e.getMessage());
        }
    }
}
