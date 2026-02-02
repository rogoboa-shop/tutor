package com.rogoboa.tutor.bookings;

import com.rogoboa.tutor.slots.AvailabilitySlot;
import com.rogoboa.tutor.usermanagement.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "bookings")
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name = "booking_class")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public abstract class Booking {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    private String subject;

    @Enumerated(EnumType.STRING)
    private BookingStatus status = BookingStatus.PENDING;

    private LocalDateTime createdAt;

    @OneToMany(mappedBy = "booking", cascade = CascadeType.ALL)
    private List<AvailabilitySlot> confirmedSlots;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
    }
}