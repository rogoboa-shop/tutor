package com.rogoboa.tutor.slots;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "availability_slots")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class AvailabilitySlot {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // Which subject is this slot for? (e.g., "Maths", "Physics")
    private String subject;

    // Which grade level is this for? (e.g., "11", "12")
    private String grade;

    // The actual start time of the slot
    private LocalDateTime startTime;

    // The end time (usually 1 hour later)
    private LocalDateTime endTime;

    // Is it already taken by another student?
    private boolean isBooked = false;

    // Optional: Link to a specific tutor if you have multiple
    private String tutorName;
}