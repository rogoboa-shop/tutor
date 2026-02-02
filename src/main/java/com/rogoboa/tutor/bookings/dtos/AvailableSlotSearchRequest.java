package com.rogoboa.tutor.bookings.dtos;

import lombok.*;

import java.time.LocalDateTime;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class AvailableSlotSearchRequest {
    private String subject;
    private String grade;
    private LocalDateTime fromDate;
    private LocalDateTime toDate;
}