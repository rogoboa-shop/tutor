package com.rogoboa.tutor.subcription;

import com.rogoboa.tutor.usermanagement.User;
import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "subscriptions")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Subscription {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // --- Payment Details ---
    // --- Payment Details ---
    // Precision 10, Scale 2 allows up to 99,999,999.99
    @Column(precision = 10, scale = 2)
    private BigDecimal baseAmount; // Their sliding scale choice (e.g., 900.00)

    private boolean hasEmergencySupport; // From the selectable card

    @Column(precision = 10, scale = 2)
    private BigDecimal totalPaid; // baseAmount + (emergency ? 250 : 0)

    private String paystackReference; // The unique ID from Paystack transaction

    // --- Status & Timing ---
    @Enumerated(EnumType.STRING)
    private SubscriptionStatus status; // ACTIVE, CANCELLED, EXPIRED

    private LocalDateTime startDate;

    private LocalDateTime nextBillingDate;

    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.startDate = LocalDateTime.now();
        this.nextBillingDate = LocalDateTime.now().plusMonths(1);
    }
}
