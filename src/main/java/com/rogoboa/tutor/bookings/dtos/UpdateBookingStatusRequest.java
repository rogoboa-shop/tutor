package com.rogoboa.tutor.bookings.dtos;

import com.rogoboa.tutor.bookings.BookingStatus;
import lombok.*;

import java.util.List;
import java.util.UUID;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class UpdateBookingStatusRequest {
    private BookingStatus status;
    private List<UUID> confirmedSlotIds;
}
