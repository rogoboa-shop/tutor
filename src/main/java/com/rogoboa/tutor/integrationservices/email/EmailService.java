package com.rogoboa.tutor.integrationservices.email;

import com.rogoboa.tutor.usermanagement.ContactType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.context.Context;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;

    @Value("${app.email.from}")
    private String fromEmail;

    @Value("${app.email.from-name}")
    private String fromName;

    @Value("${app.base-url}")
    private String baseUrl;

    /**
     * Send email verification with OTP
     */
    @Async
    public void sendVerificationEmailWithOTP(String toEmail, String otp, String fullName) {
        try {
            Context context = new Context();
            context.setVariable("name", fullName);
            context.setVariable("otp", otp);
            context.setVariable("expiryMinutes", 10);

            String htmlContent = templateEngine.process("email-verification-otp", context);

            sendHtmlEmail(toEmail, "Verify Your Email - Rogoboa Tutor", htmlContent);

            log.info("Verification OTP email sent successfully to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send verification OTP email to: {}", toEmail, e);
            throw new RuntimeException("Failed to send verification email", e);
        }
    }

    /**
     * Send password reset email with OTP
     */
    @Async
    public void sendPasswordResetEmailWithOTP(String toEmail, String otp, String fullName) {
        try {
            Context context = new Context();
            context.setVariable("name", fullName);
            context.setVariable("otp", otp);
            context.setVariable("expiryMinutes", 15);

            String htmlContent = templateEngine.process("password-reset-otp", context);

            sendHtmlEmail(toEmail, "Reset Your Password - Rogoboa Tutor", htmlContent);

            log.info("Password reset OTP email sent successfully to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send password reset OTP email to: {}", toEmail, e);
            throw new RuntimeException("Failed to send password reset email", e);
        }
    }

    /**
     * Legacy method with token-based verification (kept for backward compatibility)
     */
    @Async
    public void sendVerificationEmail(String toEmail, String token, String fullName) {
        try {
            String verificationLink = baseUrl + "/api/auth/verify-email?token=" + token;

            Context context = new Context();
            context.setVariable("name", fullName);
            context.setVariable("verificationLink", verificationLink);

            String htmlContent = templateEngine.process("email-verification", context);

            sendHtmlEmail(toEmail, "Verify Your Email - Rogoboa Tutor", htmlContent);

            log.info("Verification email sent successfully to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send verification email to: {}", toEmail, e);
        }
    }

    @Async
    public void sendContactVerification(String contact, String token, ContactType type) {
        try {
            if (type == ContactType.EMAIL) {
                String verificationLink = baseUrl + "/api/user/verify-contact?token=" + token;

                Context context = new Context();
                context.setVariable("contactType", type.toString());
                context.setVariable("verificationLink", verificationLink);

                String htmlContent = templateEngine.process("contact-verification", context);

                sendHtmlEmail(contact, "Verify Your Contact - Rogoboa Tutor", htmlContent);

                log.info("Contact verification email sent to: {}", contact);
            } else {
                // For WhatsApp/SMS, you would use Twilio or similar service
                log.info("SMS/WhatsApp verification for {} - Type: {}", contact, type);
                // TODO: Implement SMS/WhatsApp sending via Twilio
            }
        } catch (Exception e) {
            log.error("Failed to send contact verification to: {}", contact, e);
        }
    }

    @Async
    public void sendPasswordResetEmail(String toEmail, String token, String fullName) {
        try {
            String resetLink = baseUrl + "/api/auth/reset-password?token=" + token;

            Context context = new Context();
            context.setVariable("name", fullName);
            context.setVariable("resetLink", resetLink);

            String htmlContent = templateEngine.process("password-reset", context);

            sendHtmlEmail(toEmail, "Reset Your Password - Rogoboa Tutor", htmlContent);

            log.info("Password reset email sent successfully to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send password reset email to: {}", toEmail, e);
        }
    }

    @Async
    public void sendWelcomeEmail(String toEmail, String fullName) {
        try {
            Context context = new Context();
            context.setVariable("name", fullName);

            String htmlContent = templateEngine.process("welcome", context);

            sendHtmlEmail(toEmail, "Welcome to Rogoboa Tutor!", htmlContent);

            log.info("Welcome email sent successfully to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send welcome email to: {}", toEmail, e);
        }
    }

    private void sendHtmlEmail(String to, String subject, String htmlContent) throws MessagingException, UnsupportedEncodingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(
                message,
                MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED,
                StandardCharsets.UTF_8.name()
        );

        helper.setFrom(fromEmail, fromName);
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlContent, true);

        mailSender.send(message);
    }

    // Simple plain text email method (fallback)
    @Async
    public void sendSimpleEmail(String to, String subject, String text) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setFrom(fromEmail, fromName);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(text, false);

            mailSender.send(message);
            log.info("Simple email sent to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send simple email to: {}", to, e);
        }
    }
}