package com.teachCode.springSecurity.controller;

import com.teachCode.springSecurity.service.ForgotPasswordService;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.logging.Logger;
@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
public class PasswordController {

/*
    private static final Logger log = (Logger) LoggerFactory.getLogger(PasswordController.class);
*/

    @Autowired
    private ForgotPasswordService forgotPasswordService;

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestParam("email") String email) {
        String response = forgotPasswordService.forgotPassword(email);

        // Assuming the token is generated in the forgotPassword method, we log it here
        log.info("Generated reset token for email {}: {}",
                email, forgotPasswordService.getGeneratedToken(email));

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestParam("token") String token,
                                                @RequestParam("newPassword") String newPassword) {
        String result = forgotPasswordService.resetPassword(token, newPassword);

        // Log the token when trying to reset the password
        log.info("Attempting to reset password using token: {}", token);

        return new ResponseEntity<>(result, HttpStatus.OK);
    }
}
