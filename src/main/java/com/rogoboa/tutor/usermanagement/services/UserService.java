package com.rogoboa.tutor.usermanagement.services;

import com.rogoboa.tutor.integrationservices.email.EmailService;
import com.rogoboa.tutor.usermanagement.*;
import com.rogoboa.tutor.usermanagement.dtos.AddContactRequest;
import com.rogoboa.tutor.usermanagement.dtos.ContactResponse;
import com.rogoboa.tutor.usermanagement.dtos.UpdateProfileRequest;
import com.rogoboa.tutor.usermanagement.dtos.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final UserContactRepository contactRepository;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;

    public UserResponse getUserProfile(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return new UserResponse(
                user.getId(),
                user.getFullName(),
                user.getEmail(),
                user.getProfilePictureUrl(),
                user.isEmailVerified()
        );
    }

    @Transactional
    public UserResponse updateProfile(String email, UpdateProfileRequest request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (request.fullName() != null) {
            user.setFullName(request.fullName());
        }
        if (request.bio() != null) {
            user.setBio(request.bio());
        }
        if (request.schoolName() != null) {
            user.setSchoolName(request.schoolName());
        }
        if (request.grade() != null) {
            user.setGrade(request.grade());
        }
        if (request.profilePictureUrl() != null) {
            user.setProfilePictureUrl(request.profilePictureUrl());
        }

        User savedUser = userRepository.save(user);

        return new UserResponse(
                savedUser.getId(),
                savedUser.getFullName(),
                savedUser.getEmail(),
                savedUser.getProfilePictureUrl(),
                savedUser.isEmailVerified()
        );
    }

    @Transactional
    public void changePassword(String email, String oldPassword, String newPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new RuntimeException("Current password is incorrect");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    // --- Contact Management ---

    @Transactional
    public ContactResponse addContact(String email, AddContactRequest request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Check if contact already exists
        if (contactRepository.existsByUserIdAndTypeAndValue(user.getId(), request.type(), request.value())) {
            throw new RuntimeException("Contact already exists");
        }

        String verificationToken = UUID.randomUUID().toString();

        UserContact contact = UserContact.builder()
                .user(user)
                .type(request.type())
                .value(request.value())
                .verified(false)
                .verificationToken(verificationToken)
                .verificationTokenExpiry(LocalDateTime.now().plusHours(24))
                .build();

        UserContact savedContact = contactRepository.save(contact);

        // Send verification
        emailService.sendContactVerification(savedContact.getValue(), verificationToken, savedContact.getType());

        return new ContactResponse(
                savedContact.getId(),
                savedContact.getType(),
                savedContact.getValue(),
                savedContact.isVerified()
        );
    }

    @Transactional
    public void verifyContact(String token) {
        UserContact contact = contactRepository.findByVerificationToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid verification token"));

        if (contact.getVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Verification token has expired");
        }

        contact.setVerified(true);
        contact.setVerificationToken(null);
        contact.setVerificationTokenExpiry(null);
        contact.setVerifiedAt(LocalDateTime.now());
        contactRepository.save(contact);
    }

    public List<ContactResponse> getAllContacts(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return contactRepository.findByUserId(user.getId()).stream()
                .map(contact -> new ContactResponse(
                        contact.getId(),
                        contact.getType(),
                        contact.getValue(),
                        contact.isVerified()
                ))
                .collect(Collectors.toList());
    }

    @Transactional
    public void setPrimaryContact(String email, UUID contactId) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        UserContact contact = contactRepository.findById(contactId)
                .orElseThrow(() -> new RuntimeException("Contact not found"));

        if (!contact.getUser().getId().equals(user.getId())) {
            throw new RuntimeException("Unauthorized");
        }

        if (!contact.isVerified()) {
            throw new RuntimeException("Contact must be verified before setting as primary");
        }

        // 1. Unset current primary using updated repo method
        contactRepository.findByUserIdAndPrimaryContactTrue(user.getId())
                .ifPresent(current -> {
                    current.setPrimaryContact(false);
                    contactRepository.save(current);
                });

        // 2. Set new primary
        contact.setPrimaryContact(true);
        contactRepository.save(contact); // Only need this once
    }


    @Transactional
    public void deleteContact(String email, UUID contactId) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        UserContact contact = contactRepository.findById(contactId)
                .orElseThrow(() -> new RuntimeException("Contact not found"));

        if (!contact.getUser().getId().equals(user.getId())) {
            throw new RuntimeException("Unauthorized");
        }

        contactRepository.delete(contact);
    }
}
