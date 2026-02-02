package com.rogoboa.tutor.bookings.dtos;

import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class SlotResponse {
    private UUID id;
    private String subject;
    private String grade;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private boolean isBooked;
    private String tutorName;
    private String sessionType;
}