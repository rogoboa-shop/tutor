package com.rogoboa.tutor.bookings.regular.dtos;

import lombok.*;

import java.util.List;
import java.util.UUID;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class CreateRegularBookingRequest {
    private String subject;
    private List<UUID> slotIds; // IDs of available slots to book
    private String subscriptionId;
}
