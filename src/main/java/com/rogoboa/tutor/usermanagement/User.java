package com.rogoboa.tutor.usermanagement;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // --- Core Authentication ---
    @NotBlank
    @Column(unique = true)
    @Email
    private String email;

    @NotBlank
    private String password;

    @NotBlank
    private String fullName;

    // --- Email Verification ---
    @Builder.Default
    private boolean emailVerified = false;

    private String emailVerificationToken;

    private LocalDateTime emailVerificationTokenExpiry;

    // --- Profile & Visuals ---
    private String profilePictureUrl;

    private String bio;

    // --- Contact Information ---
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<UserContact> contacts = new ArrayList<>();

    // --- Education ---
    private String schoolName;

    private String grade;

    // --- Preferences & Settings ---
    @ElementCollection
    @CollectionTable(name = "user_preferences", joinColumns = @JoinColumn(name = "user_id"))
    @MapKeyColumn(name = "preference_key")
    @Column(name = "preference_value")
    private Map<String, String> preferences;

    // --- Account Metadata ---
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private UserRole role = UserRole.STUDENT;

    private LocalDateTime createdAt;

    private LocalDateTime lastLogin;

    @Builder.Default
    private boolean isActive = true;

    // --- Helper Methods ---
    public void addContact(UserContact contact) {
        contacts.add(contact);
        contact.setUser(this);
    }

    public void removeContact(UserContact contact) {
        contacts.remove(contact);
        contact.setUser(null);
    }

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    // --- UserDetails Implementation Methods ---

    @Override
    public java.util.Collection<? extends org.springframework.security.core.GrantedAuthority> getAuthorities() {
        // This converts your UserRole enum into a Spring Security Authority
        return List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getUsername() {
        return email; // Spring Security uses this as the unique identifier
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // Set to true if you don't want accounts to expire
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // Set to true if you don't have locking logic yet
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // Set to true so passwords stay valid
    }

    @Override
    public boolean isEnabled() {
        return isActive; // This links to your isActive field
    }
}