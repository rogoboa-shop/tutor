package com.rogoboa.tutor.bookings;

import com.rogoboa.tutor.bookings.dtos.*;
import com.rogoboa.tutor.bookings.tutor.TutorBookingFilterRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
public class TutorBookingService {

    private final BookingRepository bookingRepository;
    private final BookingService bookingService;

    public Page<BookingResponse> getMyBookings(UUID tutorId, Pageable pageable) {
        return bookingRepository.findByTutorId(tutorId, pageable)
                .map(bookingService::mapToResponse);
    }

    public Page<BookingResponse> getConfirmedBookings(UUID tutorId, Pageable pageable) {
        return bookingRepository.findByTutorIdAndStatus(tutorId, BookingStatus.CONFIRMED, pageable)
                .map(bookingService::mapToResponse);
    }

    public Page<BookingResponse> getOtherTutorsBookings(UUID tutorId, Pageable pageable) {
        return bookingRepository.findByTutorIdNot(tutorId, pageable)
                .map(bookingService::mapToResponse);
    }

    public Page<BookingResponse> getMissedBookings(UUID tutorId, Pageable pageable) {
        return bookingRepository.findMissedByTutorId(tutorId, LocalDateTime.now(), pageable)
                .map(bookingService::mapToResponse);
    }

    public Page<BookingResponse> getCancelledBookings(UUID tutorId, Pageable pageable) {
        return bookingRepository.findByTutorIdAndStatus(tutorId, BookingStatus.CANCELLED, pageable)
                .map(bookingService::mapToResponse);
    }

    public Page<BookingResponse> getPendingBookings(UUID tutorId, Pageable pageable) {
        return bookingRepository.findByTutorIdAndStatus(tutorId, BookingStatus.PENDING, pageable)
                .map(bookingService::mapToResponse);
    }

    public Page<BookingResponse> getBookingsByDateRange(UUID tutorId, LocalDateTime from, LocalDateTime to, Pageable pageable) {
        return bookingRepository.findByTutorIdAndDateRange(tutorId, from, to, pageable)
                .map(bookingService::mapToResponse);
    }

    @Transactional
    public BookingResponse updateStatus(UUID tutorId, UUID bookingId, UpdateBookingStatusRequest request) {
        Booking booking = bookingRepository.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));

        // Direct ID check instead of String name check
        if (!booking.getTutor().getId().equals(tutorId)) {
            throw new IllegalStateException("You are not authorized to update this booking.");
        }

        return bookingService.updateBookingStatus(bookingId, request);
    }

    public Page<BookingResponse> filterBookings(UUID tutorId, TutorBookingFilterRequest filter, Pageable pageable) {

        // Handle "Show Missed" shortcut logic
        if (Boolean.TRUE.equals(filter.isShowMissed())) {
            return getMissedBookings(tutorId, pageable);
        }

        // Use Specification for dynamic filtering
        Specification<Booking> spec = BookingSpecifications.filterBy(tutorId, filter);

        return bookingRepository.findAll(spec, pageable)
                .map(bookingService::mapToResponse);
    }

    // Add to TutorBookingService.java
    public TutorStatsResponse getTutorStatistics(UUID tutorId) {
        LocalDateTime now = LocalDateTime.now();

        // Basic Counts
        long pending = bookingRepository.countByTutorIdAndStatus(tutorId, BookingStatus.PENDING);
        long confirmed = bookingRepository.countByTutorIdAndStatus(tutorId, BookingStatus.CONFIRMED);
        long cancelled = bookingRepository.countByTutorIdAndStatus(tutorId, BookingStatus.CANCELLED);

        // Missed Count (using your existing custom logic for missed)
        // We use Pageable.unpaged() to get the total count from the Page object
        long missed = bookingRepository.findMissedByTutorId(tutorId, now, Pageable.unpaged()).getTotalElements();

        // Upcoming 3 Days Breakdown
        Map<String, Long> upcoming = new LinkedHashMap<>();
        for (int i = 1; i <= 3; i++) {
            LocalDateTime startOfDay = now.plusDays(i).withHour(0).withMinute(0).withSecond(0);
            LocalDateTime endOfDay = startOfDay.withHour(23).withMinute(59).withSecond(59);

            long count = bookingRepository.countConfirmedInDateRange(tutorId, startOfDay, endOfDay);
            upcoming.put(startOfDay.toLocalDate().toString(), count);
        }

        return TutorStatsResponse.builder()
                .pendingCount(pending)
                .confirmedCount(confirmed)
                .missedCount(missed)
                .cancelledCount(cancelled)
                .upcomingThreeDays(upcoming)
                .build();
    }
}