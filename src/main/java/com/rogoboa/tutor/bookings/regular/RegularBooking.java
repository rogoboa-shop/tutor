package com.rogoboa.tutor.bookings.regular;

import com.rogoboa.tutor.bookings.Booking;
import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;

@Entity
@DiscriminatorValue("REGULAR")
@Getter
@Setter
public class RegularBooking extends Booking {

    //private String subscriptionId;
    private boolean isPaid;
    private Integer lessonNumberInSeries; // e.g., Lesson 4 of 10
}