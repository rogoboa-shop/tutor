package com.rogoboa.tutor.usermanagement;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "user_contacts")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserContact {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ContactType type; // PHONE, WHATSAPP, EMAIL

    @NotBlank
    @Column(nullable = false)
    private String value; // The actual phone number or email

    @Builder.Default
    private boolean verified = false;

    private String verificationToken;

    private LocalDateTime verificationTokenExpiry;

    // Change this line
    @Builder.Default
    private boolean primaryContact = false;

    private LocalDateTime createdAt;

    private LocalDateTime verifiedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
