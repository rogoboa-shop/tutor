package com.rogoboa.tutor.usermanagement.services;

import com.rogoboa.tutor.usermanagement.dtos.*;
import com.rogoboa.tutor.usermanagement.services.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/profile")
    public ResponseEntity<ApiResponse<UserResponse>> getProfile(Authentication authentication) {
        String email = authentication.getName();
        UserResponse user = userService.getUserProfile(email);
        return ResponseEntity.ok(new ApiResponse<>(true, "Profile retrieved", user));
    }

    @PutMapping("/profile")
    public ResponseEntity<ApiResponse<UserResponse>> updateProfile(
            Authentication authentication,
            @Valid @RequestBody UpdateProfileRequest request
    ) {
        String email = authentication.getName();
        UserResponse user = userService.updateProfile(email, request);
        return ResponseEntity.ok(new ApiResponse<>(true, "Profile updated successfully", user));
    }

    @PostMapping("/change-password")
    public ResponseEntity<ApiResponse<Void>> changePassword(
            Authentication authentication,
            @RequestBody ChangePasswordRequest request
    ) {
        String email = authentication.getName();
        userService.changePassword(email, request.oldPassword(), request.newPassword());
        return ResponseEntity.ok(new ApiResponse<>(true, "Password changed successfully", null));
    }

    // --- Contact Management ---

    @PostMapping("/contacts")
    public ResponseEntity<ApiResponse<ContactResponse>> addContact(
            Authentication authentication,
            @Valid @RequestBody AddContactRequest request
    ) {
        String email = authentication.getName();
        ContactResponse contact = userService.addContact(email, request);
        return ResponseEntity.ok(new ApiResponse<>(true, "Contact added. Verification sent.", contact));
    }

    @GetMapping("/contacts")
    public ResponseEntity<ApiResponse<List<ContactResponse>>> getAllContacts(Authentication authentication) {
        String email = authentication.getName();
        List<ContactResponse> contacts = userService.getAllContacts(email);
        return ResponseEntity.ok(new ApiResponse<>(true, "Contacts retrieved", contacts));
    }

    @GetMapping("/verify-contact")
    public ResponseEntity<ApiResponse<Void>> verifyContact(@RequestParam String token) {
        userService.verifyContact(token);
        return ResponseEntity.ok(new ApiResponse<>(true, "Contact verified successfully", null));
    }

    @PutMapping("/contacts/{contactId}/set-primary")
    public ResponseEntity<ApiResponse<Void>> setPrimaryContact(
            Authentication authentication,
            @PathVariable UUID contactId
    ) {
        String email = authentication.getName();
        userService.setPrimaryContact(email, contactId);
        return ResponseEntity.ok(new ApiResponse<>(true, "Primary contact updated", null));
    }

    @DeleteMapping("/contacts/{contactId}")
    public ResponseEntity<ApiResponse<Void>> deleteContact(
            Authentication authentication,
            @PathVariable UUID contactId
    ) {
        String email = authentication.getName();
        userService.deleteContact(email, contactId);
        return ResponseEntity.ok(new ApiResponse<>(true, "Contact deleted", null));
    }
}