package com.oruxa.model.service.security;


import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.util.JSONPObject;
import com.oruxa.model.exception.InvalidTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import jdk.nashorn.internal.parser.JSONParser;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;
import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class AuthService {
    static String AUTHSERVICE_SERVER_URL= "http://localhost:8080";
    static String AUTHSERVICE_SERVER_URL_GET_PUBLIC_KEY_URL= AUTHSERVICE_SERVER_URL + "/getPublicKey";

    static String publicKey="";
    static String keyId="";

    public static Jws<Claims> isTokenValid(String token) {
        Jws<Claims> jwsClaims;




        try{
            if(publicKey.isEmpty()) {
                keyId = parseKeyId(token);
                publicKey=getPublicKey(AUTHSERVICE_SERVER_URL_GET_PUBLIC_KEY_URL, keyId);
            }

        }catch (UnsupportedEncodingException ex){
            ex.printStackTrace();
        }

        try {
            jwsClaims = Jwts.parser()
                    .setSigningKey(publicKey)
                    .parseClaimsJws(token);
        } catch (Exception ex) {
            throw new InvalidTokenException("Invalid token for keyId:" + keyId);
        }

        return jwsClaims;
    }

    private static String parseKeyId(String token) throws UnsupportedEncodingException {


        byte[] decodedBytes = new byte[0];
        try {
            ObjectMapper om = new ObjectMapper();
            final ObjectReader reader = om.reader();
            byte[] bytes = Base64.getDecoder().decode(token.split("\\.")[1]);

            JsonNode claims = reader.readTree(new ByteArrayInputStream(bytes));

            keyId = claims.get("jti").toString();
            return keyId;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return new String(decodedBytes, "UTF-8");

    }


    public static String getPublicKey(String url, String keyId) {

        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.set("keyId", keyId);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        HttpEntity<String> entity = new HttpEntity<String>("parameters", headers);

        ResponseEntity<String> result = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);

        return result.getBody();
    }
}
