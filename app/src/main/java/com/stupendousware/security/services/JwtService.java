package com.stupendousware.security.services;

import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
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
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
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
    public String grantToken(User user, String publicPemFilePath, String privatePemFilePath)
            throws Exception {
        try {
            var publicKey = getPublicKeyFromPem(publicPemFilePath);
            var privateKey = getPrivateKeyFromPem(privatePemFilePath);
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

    /**
     * @param user
     * @param publicKeyFilePath
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws JOSEException
     */
    public String grantEncryptedToken(User user, String publicKeyFilePath)
            throws Exception {
        var header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
        var publicKey = getPublicKeyFromPem(publicKeyFilePath);
        var encrypter = new RSAEncrypter(publicKey);
        var claims = new JWTClaimsSet.Builder()
                .subject(user.id())
                .audience(user.requestor())
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(10, ChronoUnit.MINUTES)))
                .build();
        var jwt = new EncryptedJWT(header, claims);
        jwt.encrypt(encrypter);
        var token = jwt.serialize();
        System.out.print("encrypted token: " + token);
        return token;
    }

    /**
     * @param token
     * @param privateKeyFilePath
     * @throws PKCSException
     * @throws ParseException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws JOSEException
     */
    public void verifyEncryptedToken(String token, String privateKeyFilePath)
            throws PKCSException, ParseException, InvalidKeySpecException, NoSuchAlgorithmException, IOException,
            JOSEException {
        var jwt = EncryptedJWT.parse(token);
        var privateKey = getPrivateKeyFromPem(privateKeyFilePath);
        var decrypter = new RSADecrypter(privateKey);
        jwt.decrypt(decrypter);
        var payload = jwt.getPayload();
        System.out.print("issuer: " + payload.toString());
    }

    public DecodedJWT verify(String token, String publicKeyFilePath, String privateKeyFilePath)
            throws Exception {
        var publicKey = getPublicKeyFromPem(publicKeyFilePath);
        var privateKey = getPrivateKeyFromPem(privateKeyFilePath);
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
            throws Exception {
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
