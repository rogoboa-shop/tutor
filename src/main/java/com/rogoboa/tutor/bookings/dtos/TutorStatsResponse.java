package com.rogoboa.tutor.bookings.dtos;

import lombok.Builder;
import lombok.Data;
import java.util.Map;

@Data
@Builder
public class TutorStatsResponse {
    private long pendingCount;
    private long confirmedCount;
    private long missedCount;
    private long cancelledCount;

    // Key: Date (e.g., "2026-02-09"), Value: Count of confirmed bookings
    private Map<String, Long> upcomingThreeDays;
}