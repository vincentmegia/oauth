package com.stupendousware.security.services;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;

@Service
public class JwtService {
    /**
     * @param publicKey
     * @param privateKey
     * @return
     * @throws JWTCreationException
     */
    public String grantToken(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws JWTCreationException {
        try {
            var alogrithm = Algorithm.RSA256(publicKey, privateKey);
            var token = JWT.create()
                    .withIssuer("stupendousware")
                    .sign(alogrithm);
            return token;
        } catch (JWTCreationException e) {
            throw e;
        }
    }

    /**
     * @param fileName
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public RSAPublicKey getPublicKeyFromPem(String fileName)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        var pemString = new String(Files.readString(Path.of(fileName)));
        var keyString = pemString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");
        var bytes = Base64.getDecoder().decode(keyString);
        var keyFactory = KeyFactory.getInstance("RSA");
        var keySpec = new X509EncodedKeySpec(bytes);
        var key = keyFactory.generatePublic(keySpec);
        return (RSAPublicKey) key;
    }

    /**
     * @param fileName
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public RSAPrivateKey getPrivateKeyFromPem(String fileName)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, PKCSException {
        PrivateKeyInfo pki;

        Security.addProvider(new BouncyCastleProvider());
        try (var pemParser = new PEMParser(new FileReader(fileName))) {
            var result = pemParser.readObject();
            var epki = (PKCS8EncryptedPrivateKeyInfo) result;
            var builder = new JcePKCSPBEInputDecryptorProviderBuilder()
                    .setProvider("BC");
            var idp = builder.build("abc.123".toCharArray());
            pki = epki.decryptPrivateKeyInfo(idp);
        } catch (Exception e) {
            throw e;
        }
        var converter = new JcaPEMKeyConverter().setProvider("BC");
        return (RSAPrivateKey) converter.getPrivateKey(pki);
    }
}
