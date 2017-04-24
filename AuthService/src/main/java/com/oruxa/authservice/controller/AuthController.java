package com.oruxa.authservice.controller;

import com.oruxa.authservice.service.AuthService;
import com.oruxa.model.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;

@RestController
public class AuthController {
    //static final int EXPIRATION_TIME = 10 * 24 * 3600 * 1000;


    @Autowired
    AuthService authService;

    @RequestMapping("/getToken")
    public String getToken(HttpServletRequest request) {


        User user = authService.isValidUser(request.getHeader("email"), request.getHeader("password"));

        if (user != null) {
            return authService.generateToken(user.getUsername());
        } else {
            return "";
        }
    }


    @RequestMapping("/getPublicKey")
    public String getPublicKey(HttpServletRequest request) {

        String keyId = (request.getHeader("keyId"));

        if (keyId != null) {
            return authService.getPublicKey();
        } else {
            return "";
        }
    }
}
