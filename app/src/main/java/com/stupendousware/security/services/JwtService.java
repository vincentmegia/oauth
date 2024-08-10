package com.stupendousware.security.services;

import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.stupendousware.security.models.User;

@Service
public class JwtService {
    /**
     * 
     */
    public JwtService() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * @param user
     * @param publicKey
     * @param privateKey
     * @return
     * @throws JWTCreationException
     */
    public String grantToken(User user, RSAPublicKey publicKey, RSAPrivateKey privateKey) throws JWTCreationException {
        try {
            var alogrithm = Algorithm.RSA256(publicKey, privateKey);
            var token = JWT.create()
                    .withIssuer("stupendousware")
                    .withSubject(user.id())
                    .withAudience(user.requestor())
                    .withIssuedAt(Instant.now())
                    .withExpiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                    .sign(alogrithm);
            return token;
        } catch (JWTCreationException e) {
            throw e;
        }
    }

    public DecodedJWT verify(String token, RSAPublicKey publicKey, RSAPrivateKey privateKey)
            throws JWTVerificationException {
        var algorith = Algorithm.RSA256(publicKey, privateKey);
        var verifier = JWT.require(algorith)
                .withIssuer("stupendousware")
                .build();
        return verifier.verify(token);
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
        try (var pemParser = new PEMParser(new FileReader(fileName))) {
            var converter = new JcaPEMKeyConverter();
            var publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
            return (RSAPublicKey) converter.getPublicKey(publicKeyInfo);
        } catch (Exception e) {
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
    public RSAPrivateKey getPrivateKeyFromPem(String fileName)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, PKCSException {
        PrivateKeyInfo pki;

        try (var pemParser = new PEMParser(new FileReader(fileName))) {
            var result = (PKCS8EncryptedPrivateKeyInfo) pemParser.readObject();
            var builder = new JcePKCSPBEInputDecryptorProviderBuilder()
                    .setProvider("BC");
            var idp = builder.build("abc.123".toCharArray());
            pki = result.decryptPrivateKeyInfo(idp);
        } catch (Exception e) {
            throw e;
        }
        var converter = new JcaPEMKeyConverter().setProvider("BC");
        return (RSAPrivateKey) converter.getPrivateKey(pki);
    }
}
