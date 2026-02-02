package com.rogoboa.tutor.bookings.dtos;

import com.rogoboa.tutor.bookings.BookingStatus;
import lombok.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class BookingResponse {
    private UUID id;
    private UUID userId;
    private String userFullName;
    private String subject;
    private BookingStatus status;
    private String bookingType; // "TRIAL" or "REGULAR"
    private LocalDateTime createdAt;
    private List<SlotResponse> confirmedSlots;

    // Trial-specific fields
    private String topicOfInterest;
    private List<String> preferredSlots;
    private String customRequest;

    // Regular-specific fields
    private String subscriptionId;
    private Boolean isPaid;
    private Integer lessonNumberInSeries;
}