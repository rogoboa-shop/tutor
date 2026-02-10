package com.rogoboa.tutor.bookings.tutor;

import com.rogoboa.tutor.bookings.BookingStatus;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Filter payload posted (or received as query params) by a tutor
 * to narrow down their booking list.
 *
 * Every field except {@code showMissed} is optional — the service
 * treats nulls as "no constraint on this dimension".
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class TutorBookingFilterRequest {

    /** Narrow to a single status.  Null → all statuses. */
    private BookingStatus status;

    /** Narrow to TRIAL | REGULAR.  Null → both types. */
    private String bookingType;  // "TRIAL" or "REGULAR"

    /** Narrow to a specific subject (e.g. "Mathematics"). */
    private String subject;

    /** Inclusive start of the createdAt window. */
    private LocalDateTime fromDate;

    /** Inclusive end of the createdAt window. */
    private LocalDateTime toDate;

    /**
     * When {@code true} the service returns only bookings that are
     * considered "missed": status is still CONFIRMED but every
     * confirmed slot's {@code endTime} is already in the past.
     *
     * Overrides {@code status} when set — the query pins status to
     * CONFIRMED and adds the time filter automatically.
     */
    private boolean showMissed = false;
}
