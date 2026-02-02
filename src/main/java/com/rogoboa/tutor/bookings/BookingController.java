package com.rogoboa.tutor.bookings;

import com.rogoboa.tutor.bookings.dtos.*;
import com.rogoboa.tutor.bookings.regular.dtos.CreateRegularBookingRequest;
import com.rogoboa.tutor.bookings.trial.dtos.CreateTrialBookingRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/bookings")
@RequiredArgsConstructor
public class BookingController {

    private final BookingService bookingService;

    // ============= CREATE BOOKINGS =============

    @PostMapping("/student/trial")
    @PreAuthorize("hasAnyRole('STUDENT', 'ADMIN')")
    public ResponseEntity<BookingResponse> createTrialBooking(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody CreateTrialBookingRequest request) {

        UUID userId = getUserIdFromPrincipal(userDetails);
        BookingResponse response = bookingService.createTrialBooking(userId, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/student/regular")
    @PreAuthorize("hasAnyRole('STUDENT', 'ADMIN')")
    public ResponseEntity<BookingResponse> createRegularBooking(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody CreateRegularBookingRequest request) {

        UUID userId = getUserIdFromPrincipal(userDetails);
        BookingResponse response = bookingService.createRegularBooking(userId, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ============= READ BOOKINGS =============

    @GetMapping
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<List<BookingResponse>> getAllBookings() {
        List<BookingResponse> bookings = bookingService.getAllBookings();
        return ResponseEntity.ok(bookings);
    }

    @GetMapping("/student/my-bookings")
    @PreAuthorize("hasAnyRole('STUDENT', 'TUTOR', 'ADMIN')")
    public ResponseEntity<List<BookingResponse>> getMyBookings(
            @AuthenticationPrincipal UserDetails userDetails) {

        UUID userId = getUserIdFromPrincipal(userDetails);
        List<BookingResponse> bookings = bookingService.getUserBookings(userId);
        return ResponseEntity.ok(bookings);
    }

    @GetMapping("/student/{bookingId}")
    @PreAuthorize("hasAnyRole('STUDENT', 'TUTOR', 'ADMIN')")
    public ResponseEntity<BookingResponse> getBookingById(@PathVariable UUID bookingId) {
        BookingResponse booking = bookingService.getBookingById(bookingId);
        return ResponseEntity.ok(booking);
    }

    @GetMapping("/pending-trials")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<List<BookingResponse>> getPendingTrials() {
        List<BookingResponse> trials = bookingService.getPendingTrials();
        return ResponseEntity.ok(trials);
    }

    // ============= UPDATE BOOKINGS =============

    @PatchMapping("/{bookingId}/status")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<BookingResponse> updateBookingStatus(
            @PathVariable UUID bookingId,
            @Valid @RequestBody UpdateBookingStatusRequest request) {

        BookingResponse updated = bookingService.updateBookingStatus(bookingId, request);
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping("/student/{bookingId}")
    @PreAuthorize("hasAnyRole('STUDENT', 'TUTOR', 'ADMIN')")
    public ResponseEntity<Void> cancelBooking(
            @PathVariable UUID bookingId,
            @AuthenticationPrincipal UserDetails userDetails) {

        // TODO: Add authorization check to ensure user owns the booking or is admin
        bookingService.cancelBooking(bookingId);
        return ResponseEntity.noContent().build();
    }

    // ============= AVAILABILITY SLOTS =============

    @GetMapping("/student/slots/available")
    @PreAuthorize("hasAnyRole('STUDENT', 'TUTOR', 'ADMIN')")
    public ResponseEntity<List<SlotResponse>> getAvailableSlots(
            @RequestParam String subject,
            @RequestParam String grade) {

        List<SlotResponse> slots = bookingService.getAvailableSlots(subject, grade);
        return ResponseEntity.ok(slots);
    }

    @GetMapping("/student/slots/trial/available")
    @PreAuthorize("hasAnyRole('STUDENT', 'TUTOR', 'ADMIN')")
    public ResponseEntity<List<SlotResponse>> getAvailableTrialSlots(
            @RequestParam String subject,
            @RequestParam String grade) {

        List<SlotResponse> slots = bookingService.getAvailableTrialSlots(subject, grade);
        return ResponseEntity.ok(slots);
    }


    @PostMapping("/student/slots/search")
    @PreAuthorize("hasAnyRole('STUDENT', 'TUTOR', 'ADMIN')")
    public ResponseEntity<List<SlotResponse>> searchAvailableSlots(
            @Valid @RequestBody AvailableSlotSearchRequest request) {

        List<SlotResponse> slots = bookingService.searchAvailableSlots(request);
        return ResponseEntity.ok(slots);
    }

    // ============= STATISTICS =============

    @GetMapping("/summary")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<BookingSummaryResponse> getBookingSummary() {
        BookingSummaryResponse summary = bookingService.getBookingSummary();
        return ResponseEntity.ok(summary);
    }

    // ============= HELPER METHODS =============

    private UUID getUserIdFromPrincipal(UserDetails userDetails) {
        // Assuming you have a UserRepository to fetch the full User entity
        // Or you can cast UserDetails to your User class if that's what Spring Security uses
        if (userDetails instanceof com.rogoboa.tutor.usermanagement.User user) {
            return user.getId();
        }
        throw new RuntimeException("Unable to extract user ID from principal");
    }
}
