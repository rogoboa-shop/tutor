package com.rogoboa.tutor.trial;

import com.rogoboa.tutor.usermanagement.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "trial_bookings")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class TrialBooking {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @OneToOne // One free trial per registered user
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    private String subject; // Maths or Physics

    private String topic; // Optional: "Calculus", "Vectors", etc.

    // Store the 3-5 selected slots as strings or a separate table
    @ElementCollection
    @CollectionTable(name = "trial_preferred_slots", joinColumns = @JoinColumn(name = "booking_id"))
    private List<String> preferredSlots; // e.g., ["2026-01-15 09:00", "2026-01-16 14:00"]

    @Column(length = 500)
    private String customRequest; // "If these don't work..."

    @Enumerated(EnumType.STRING)
    private BookingStatus status = BookingStatus.PENDING;

    private LocalDateTime bookedAt;

    @PrePersist
    protected void onCreate() {
        this.bookedAt = LocalDateTime.now();
    }
}

enum BookingStatus {
    PENDING, CONFIRMED, COMPLETED, CANCELLED
}