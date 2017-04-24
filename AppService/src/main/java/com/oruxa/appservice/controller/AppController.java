package com.oruxa.appservice.controller;

import com.oruxa.model.model.User;
import com.oruxa.model.service.security.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class AppController {


    @RequestMapping("/getMessage")
    public String getMessage(HttpServletRequest request) {
        String token = (request.getHeader("token"));

        if (token != null) {
            AuthService.isTokenValid(token);
        }

        return "Hello World...";
    }


}
