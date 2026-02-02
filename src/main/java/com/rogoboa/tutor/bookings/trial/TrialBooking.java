package com.rogoboa.tutor.bookings.trial;

import com.rogoboa.tutor.bookings.Booking;
import jakarta.persistence.*;
import lombok.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@DiscriminatorValue("TRIAL")
@Getter @Setter
public class TrialBooking extends Booking {

    private String topicOfInterest;

    @ElementCollection
    @CollectionTable(
            name = "trial_preferred_slots",
            joinColumns = @JoinColumn(name = "booking_id", referencedColumnName = "id") // Explicitly reference the ID
    )
    @Column(name = "slot_description")
    private List<String> preferredSlots = new ArrayList<>();

    private String customRequest;
}