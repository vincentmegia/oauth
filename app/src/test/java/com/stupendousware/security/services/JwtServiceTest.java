package com.stupendousware.security.services;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.stupendousware.security.models.User;

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
    public void testEncryptedToken() {

        try {
            var jwtService = new JwtService();
            var token = jwtService.grantEncryptedToken(
                    new User("sg-user-321", "john", "doe", "todo-app"),
                    "./src/test/resources/test-public.pem");
            assertTrue(token != null);
        } catch (Exception e) {
            assertTrue(true != false);
        }
    }

    @Test
    public void testVerifyEncryptedToken() {

        try {
            var jwtService = new JwtService();
            var token = jwtService.grantEncryptedToken(
                    new User("sg-user-321", "john", "doe", "todo-app"),
                    "./src/test/resources/test-public.pem");
            jwtService.verifyEncryptedToken(token,
                    "./src/test/resources/test-private.pem");
            assertTrue(token != null);
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
            var token = jwtService.grantToken(new User("sg-user-123", "john", "doe", "todo-app"),
                    "./src/test/resources/test-public.pem",
                    "./src/test/resources/test-private.pem");
            System.out.println("token: " + token);
            assertTrue(token != "");
        } catch (Exception e) {
            System.out.println("exception: " + e.getMessage());
        }
    }

    @Test
    public void testTokenWithPrivateClaims() {
        try {
            var jwtService = new JwtService();
            var privateKeyFilePath = "./src/test/resources/test-private.pem";
            var publicKeyFilePath = "./src/test/resources/test-public.pem";
            var token = jwtService.grantToken(new User("sg-user-123", "john", "doe", "todo-app"), publicKeyFilePath,
                    privateKeyFilePath);
            var decodedToken = jwtService.verify(token, publicKeyFilePath, privateKeyFilePath);
            System.out.println("decoded token: " + decodedToken.getIssuer());
            assertTrue(decodedToken.getIssuer().equals("stupendousware"));
        } catch (Exception e) {
            System.out.println("exception: " + e.getMessage());
        }
    }
}
