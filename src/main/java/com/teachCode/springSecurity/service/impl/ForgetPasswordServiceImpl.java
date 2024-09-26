package com.teachCode.springSecurity.service.impl;

import com.teachCode.springSecurity.entities.User;
import com.teachCode.springSecurity.repository.UserRepository;
import com.teachCode.springSecurity.service.EmailService;
import com.teachCode.springSecurity.service.ForgotPasswordService;
import jakarta.transaction.Transactional;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;
@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class ForgetPasswordServiceImpl implements ForgotPasswordService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    public String forgotPassword(String email) {
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (!userOptional.isPresent()) {
            throw new IllegalArgumentException("Email not found");
        }

        User user = userOptional.get();

        // Generate a password reset token
        String generatedToken = UUID.randomUUID().toString();
        user.setResetToken(generatedToken);

        // Log the generated token for debugging
        log.info("Generated reset token for email {}: {}", email, generatedToken);

        userRepository.save(user);

        // Construct reset URL
        String resetUrl = "http://localhost:8080/api/v1/auth/reset-password?token=" + generatedToken;

        // Send the reset email
        emailService.sendEmail(email, "Password Reset Request",
                "To reset your password, click the following link: " + resetUrl);

        return "Password reset email sent!";
    }

    public String resetPassword(String token, String newPassword) {
        Optional<User> userOptional = userRepository.findByResetToken(token);

        if (!userOptional.isPresent()) {
            throw new IllegalArgumentException("Invalid token");
        }

        User user = userOptional.get();
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetToken(null); // Clear the reset token
        userRepository.save(user);

        return "Password has been reset successfully!";
    }

    public String getGeneratedToken(String email) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            return userOptional.get().getResetToken();
        }
        return null; // or throw an exception if more appropriate
    }
}
