package com.rogoboa.tutor.bookings.dtos;

import com.rogoboa.tutor.SessionType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.time.LocalDateTime;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class CreateSlotRequest {

    @NotBlank(message = "Subject is required")
    private String subject;

    @NotBlank(message = "Grade is required")
    private String grade;

    @NotNull(message = "Start time is required")
    private LocalDateTime startTime;

    @NotNull(message = "End time is required")
    private LocalDateTime endTime;

    private String tutorName;

    private SessionType sessionType;
}