package com.rogoboa.tutor.bookings.trial.dtos;

import lombok.*;

import java.util.List;
import java.util.UUID;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class CreateTrialBookingRequest {
    private String subject;
    private String topicOfInterest;
    private List<UUID> preferredSlotIds; // IDs of available slots
    private String customRequest;
}