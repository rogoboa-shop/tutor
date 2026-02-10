package com.rogoboa.tutor.bookings.tutor;

import com.rogoboa.tutor.bookings.TutorBookingService;
import com.rogoboa.tutor.bookings.dtos.*;
import com.rogoboa.tutor.usermanagement.User;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

/**
 * Tutor-facing booking endpoints.
 * * <p>Updated to use direct User/Tutor ID relationships for better performance
 * and accurate pagination.</p>
 */
@RestController
@RequestMapping("/api/bookings/tutor")
@RequiredArgsConstructor
public class TutorBookingController {

    private final TutorBookingService tutorBookingService;

    // ═══════════════════════════════════════════════════════════════
    //  OWN BOOKINGS
    // ═══════════════════════════════════════════════════════════════

    @GetMapping("/my-bookings")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<Page<BookingResponse>> getMyBookings(
            @AuthenticationPrincipal User user,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC)
            Pageable pageable) {

        return ResponseEntity.ok(tutorBookingService.getMyBookings(user.getId(), pageable));
    }

    // ═══════════════════════════════════════════════════════════════
    //  CONFIRMED
    // ═══════════════════════════════════════════════════════════════

    @GetMapping("/confirmed")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<Page<BookingResponse>> getConfirmedBookings(
            @AuthenticationPrincipal User user,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC)
            Pageable pageable) {

        return ResponseEntity.ok(tutorBookingService.getConfirmedBookings(user.getId(), pageable));
    }

    // ═══════════════════════════════════════════════════════════════
    //  OTHER TUTORS' BOOKINGS
    // ═══════════════════════════════════════════════════════════════

    @GetMapping("/other-tutors")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<Page<BookingResponse>> getOtherTutorsBookings(
            @AuthenticationPrincipal User user,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC)
            Pageable pageable) {

        return ResponseEntity.ok(tutorBookingService.getOtherTutorsBookings(user.getId(), pageable));
    }

    // ═══════════════════════════════════════════════════════════════
    //  MISSED BOOKINGS
    // ═══════════════════════════════════════════════════════════════

    @GetMapping("/missed")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<Page<BookingResponse>> getMissedBookings(
            @AuthenticationPrincipal User user,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC)
            Pageable pageable) {

        return ResponseEntity.ok(tutorBookingService.getMissedBookings(user.getId(), pageable));
    }

    // ═══════════════════════════════════════════════════════════════
    //  CANCELLED BOOKINGS
    // ═══════════════════════════════════════════════════════════════

    @GetMapping("/cancelled")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<Page<BookingResponse>> getCancelledBookings(
            @AuthenticationPrincipal User user,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC)
            Pageable pageable) {

        return ResponseEntity.ok(tutorBookingService.getCancelledBookings(user.getId(), pageable));
    }

    @GetMapping("/pending")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<Page<BookingResponse>> getPendingBookings(
            @AuthenticationPrincipal User user,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC)
            Pageable pageable) {

        return ResponseEntity.ok(tutorBookingService.getPendingBookings(user.getId(), pageable));
    }

    // ═══════════════════════════════════════════════════════════════
    //  BY DATE RANGE
    // ═══════════════════════════════════════════════════════════════

    @GetMapping("/by-date-range")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<Page<BookingResponse>> getBookingsByDateRange(
            @AuthenticationPrincipal User user,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime fromDate,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime toDate,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC)
            Pageable pageable) {

        return ResponseEntity.ok(
                tutorBookingService.getBookingsByDateRange(user.getId(), fromDate, toDate, pageable));
    }

    // ═══════════════════════════════════════════════════════════════
    //  GENERIC MULTI-FIELD FILTER
    // ═══════════════════════════════════════════════════════════════

    @PostMapping("/filter")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<Page<BookingResponse>> filterBookings(
            @AuthenticationPrincipal User user,
            @Valid @RequestBody TutorBookingFilterRequest filter,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC)
            Pageable pageable) {

        return ResponseEntity.ok(tutorBookingService.filterBookings(user.getId(), filter, pageable));
    }

    // ═══════════════════════════════════════════════════════════════
    //  UPDATE BOOKING STATUS
    // ═══════════════════════════════════════════════════════════════

    @PatchMapping("/{bookingId}/status")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<?> updateBookingStatus(
            @AuthenticationPrincipal User user,
            @PathVariable UUID bookingId,
            @Valid @RequestBody UpdateBookingStatusRequest request) {

        try {
            // Service now uses the User's ID for the ownership check
            BookingResponse updated = tutorBookingService.updateStatus(user.getId(), bookingId, request);
            return ResponseEntity.ok(updated);
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("message", e.getMessage()));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", e.getMessage()));
        }
    }


    // ═══════════════════════════════════════════════════════════════
    //  TUTOR BOOKING STATISTICS
    // ═══════════════════════════════════════════════════════════════
    @GetMapping("/statistics")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<TutorStatsResponse> getStatistics(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok(tutorBookingService.getTutorStatistics(user.getId()));
    }
}