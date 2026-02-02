package com.rogoboa.tutor.bookings.dtos;

import lombok.*;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class BookingSummaryResponse {
    private long totalBookings;
    private long pendingTrials;
    private long confirmedBookings;
    private long completedBookings;
    private long cancelledBookings;
}
