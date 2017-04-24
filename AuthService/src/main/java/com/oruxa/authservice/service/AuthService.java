package com.oruxa.authservice.service;

import com.oruxa.model.exception.InvalidTokenException;
import com.oruxa.model.exception.InvalidUserException;
import com.oruxa.model.model.User;
import com.sun.tools.javac.util.Convert;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.RsaProvider;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

@Service
public class AuthService {

    static final int EXPIRATION_TIME = 60 * 60 * 1000;
    static KeyPair keyPair=null;
    private final String CREDENTIAL_FILE_PATH = getClass().getClassLoader().getResource("credential.properties").getPath();
    static final String CREDENTIAL_PROPERTIES_PRIVATEKEY="privateKey";
    static final String CREDENTIAL_PROPERTIES_PUBLICKEY="publicKey";
    Properties credentialProp = new Properties();

    public User isValidUser(String email, String password ){
        if (email != null && password != null && email.equals("appservice@oruxa.com") && password.equals("admin")) {

            User u = new User();
            u.setEmail(email);
            u.setUsername("AppService");
            u.setUserid(1);
            return u;

        } else {
            throw new InvalidUserException("Invalid email " + email + " and/or password");
        }
    }

    private KeyPair generateCredential() {
        //check the credential.properties

        try {
            if(credentialProp.isEmpty()) {
                FileInputStream fileInputStream = new FileInputStream(CREDENTIAL_FILE_PATH);
                credentialProp.clear();
                credentialProp.load(fileInputStream);
            }
            if(credentialProp.containsKey(CREDENTIAL_PROPERTIES_PUBLICKEY) &&
                    credentialProp.containsKey(CREDENTIAL_PROPERTIES_PRIVATEKEY)){

                //bypass generating new key, existing keys could be used
                return null;
            }

        } catch (Exception ex) {

        }


        keyPair = RsaProvider.generateKeyPair(1024);
        //String kid = UUID.randomUUID().toString();


        persistKey (keyPair);
        return keyPair;
    }

    private void persistKey(KeyPair key){
        Properties properties = new Properties();

        try {

            String b64PublicKey = Base64.getEncoder().encodeToString(key.getPublic().getEncoded());
            String b64PrivateKey = Base64.getEncoder().encodeToString(key.getPrivate().getEncoded());

            FileOutputStream fileOutputStream = new FileOutputStream(CREDENTIAL_FILE_PATH);
            properties.put("privateKey", b64PrivateKey);
            properties.put("publicKey",b64PublicKey);

            properties.store(fileOutputStream,"Private and Public Key");
            fileOutputStream.close();

        } catch (Exception e) {
            e.printStackTrace();
        }


    }

    public String generateToken(String subject){
        if(true || keyPair==null){
            if (generateCredential()==null) {
                // use existing keys from credential.properties
                String pubkey = credentialProp.getProperty(CREDENTIAL_PROPERTIES_PUBLICKEY);
                String prikey = credentialProp.getProperty(CREDENTIAL_PROPERTIES_PUBLICKEY);
                PublicKey publicKey = decodePublicKeyFromBase64(pubkey);
                PrivateKey privateKey = decodePrivateKeyFromBase64(prikey);

                keyPair = new KeyPair(publicKey, privateKey);
            }

        }

        String jwt = Jwts.builder()
                .setSubject(subject)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.RS512, keyPair.getPrivate())
                .compact();

        return jwt;
    }

    public String getPublicKey(){
        if(keyPair != null){
            return keyPair.getPublic().toString();
        }
        return "";
    }


    private PublicKey decodePublicKeyFromBase64(String base64) {
        try{
            byte[] publicBytes = Base64.getDecoder().decode(base64);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
            return pubKey;

        }catch (Exception ex){
            ex.printStackTrace();
        }
        return null;

    }

    private PrivateKey decodePrivateKeyFromBase64(String base64) {
        try{
            byte[] publicBytes = Base64.getDecoder().decode(base64);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey priKey = keyFactory.generatePrivate(keySpec);
            return priKey;

        }catch (Exception ex){
            ex.printStackTrace();
        }
        return null;
    }
}
