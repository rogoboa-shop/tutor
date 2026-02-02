package com.rogoboa.tutor.bookings.dtos;

import com.rogoboa.tutor.SessionType;
import lombok.*;

import java.time.LocalDateTime;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class UpdateSlotRequest {
    private String subject;
    private String grade;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private String tutorName;
    private SessionType sessionType;
}
