package com.rogoboa.tutor.bookings;

import com.rogoboa.tutor.SessionType;
import com.rogoboa.tutor.bookings.*;
import com.rogoboa.tutor.bookings.dtos.*;
import com.rogoboa.tutor.bookings.regular.RegularBooking;
import com.rogoboa.tutor.bookings.regular.dtos.CreateRegularBookingRequest;
import com.rogoboa.tutor.bookings.trial.TrialBooking;
import com.rogoboa.tutor.bookings.trial.dtos.CreateTrialBookingRequest;
import com.rogoboa.tutor.slots.AvailabilitySlot;
import com.rogoboa.tutor.slots.AvailabilitySlotRepository;
import com.rogoboa.tutor.usermanagement.User;
import com.rogoboa.tutor.usermanagement.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class BookingService {

    private final BookingRepository bookingRepository;
    private final AvailabilitySlotRepository slotRepository;
    private final UserRepository userRepository;

    // ============= CREATE BOOKINGS =============

    @Transactional
    public BookingResponse createTrialBooking(UUID userId, CreateTrialBookingRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // NEW: Validation Logic For Number of user bookings
        List<BookingStatus> restrictedStatuses = List.of(
                BookingStatus.PENDING,
                BookingStatus.CONFIRMED,
                BookingStatus.COMPLETED
        );

        long activeCount = bookingRepository.countByUserIdAndSubjectAndStatusIn(
                userId,
                request.getSubject(),
                restrictedStatuses
        );

        if (activeCount >= 2) {
            throw new IllegalStateException(
                    "You have already reached the limit of 2 trial sessions for " + request.getSubject() + "."
            );
        }

        TrialBooking booking = new TrialBooking();
        booking.setUser(user);
        booking.setSubject(request.getSubject());
        booking.setTopicOfInterest(request.getTopicOfInterest());
        booking.setCustomRequest(request.getCustomRequest());
        booking.setStatus(BookingStatus.PENDING);

        // NEW: Link to the Tutor from the first preferred slot
        if (request.getPreferredSlotIds() != null && !request.getPreferredSlotIds().isEmpty()) {
            UUID firstSlotId = request.getPreferredSlotIds().get(0);
            AvailabilitySlot firstSlot = slotRepository.findById(firstSlotId)
                    .orElseThrow(() -> new RuntimeException("Slot not found: " + firstSlotId));

            booking.setTutor(firstSlot.getTutor()); // Assigning the tutor
        }

        // 1. SAVE THE BOOKING FIRST WITHOUT THE COLLECTION
        // This ensures the booking ID exists in the DB
        TrialBooking saved = bookingRepository.saveAndFlush(booking);

        // 2. NOW ADD THE SLOTS
        List<String> preferredSlotStrings = new ArrayList<>();
        if (request.getPreferredSlotIds() != null && !request.getPreferredSlotIds().isEmpty()) {
            for (UUID slotId : request.getPreferredSlotIds()) {
                AvailabilitySlot slot = slotRepository.findById(slotId)
                        .orElseThrow(() -> new RuntimeException("Slot not found: " + slotId));

                String formatted = slot.getStartTime().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"))
                        + " - " + slot.getEndTime().format(DateTimeFormatter.ofPattern("HH:mm"));
                preferredSlotStrings.add(formatted);
            }
        }

        // 3. UPDATE THE SAVED ENTITY
        saved.setPreferredSlots(preferredSlotStrings);

        // Final save (Hibernate will now see the ID exists and insert into the collection table)
        return mapToResponse(bookingRepository.save(saved));
    }

    @Transactional
    public BookingResponse createRegularBooking(UUID userId, CreateRegularBookingRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Verify all slots are available
        List<AvailabilitySlot> slots = slotRepository.findAllById(request.getSlotIds());
        if (slots.size() != request.getSlotIds().size()) {
            throw new RuntimeException("One or more slots not found");
        }

        for (AvailabilitySlot slot : slots) {
            if (slot.isBooked()) {
                throw new RuntimeException("Slot already booked: " + slot.getId());
            }
        }

        // Logic: All selected slots should belong to the same tutor
        User tutor = slots.get(0).getTutor();

        RegularBooking booking = new RegularBooking();
        booking.setUser(user);
        booking.setTutor(tutor);
        booking.setSubject(request.getSubject());
        booking.setStatus(BookingStatus.CONFIRMED);

        RegularBooking saved = bookingRepository.save(booking);

        // Mark slots as booked
        for (AvailabilitySlot slot : slots) {
            slot.setBooked(true);
            slot.setBooking(saved);
        }
        slotRepository.saveAll(slots);

        return mapToResponse(saved);
    }

    // ============= READ BOOKINGS =============

    public List<BookingResponse> getAllBookings() {
        return bookingRepository.findAll().stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    /*public List<BookingResponse> getUserBookings(UUID userId) {
        return bookingRepository.findByUserId(userId).stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }*/

    public Page<BookingResponse> getUserBookings(UUID userId, Pageable pageable) {
        Page<Booking> bookingPage = bookingRepository.findByUserId(userId, pageable);

        // Map the Page of entities to a Page of DTOs
        return bookingPage.map(this::mapToResponse);
    }

    public BookingResponse getBookingById(UUID bookingId) {
        Booking booking = bookingRepository.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));
        return mapToResponse(booking);
    }

    public List<BookingResponse> getPendingTrials() {
        return bookingRepository.findAllPendingTrials().stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    // ============= UPDATE BOOKINGS =============

    @Transactional
    public BookingResponse updateBookingStatus(UUID bookingId, UpdateBookingStatusRequest request) {
        Booking booking = bookingRepository.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));

        booking.setStatus(request.getStatus());

        // If confirming slots (admin action)
        if (request.getConfirmedSlotIds() != null && !request.getConfirmedSlotIds().isEmpty()) {
            List<AvailabilitySlot> slots = slotRepository.findAllById(request.getConfirmedSlotIds());

            for (AvailabilitySlot slot : slots) {
                slot.setBooked(true);
                slot.setBooking(booking);
            }
            slotRepository.saveAll(slots);
        }

        Booking updated = bookingRepository.save(booking);
        return mapToResponse(updated);
    }

    @Transactional
    public void cancelBooking(UUID bookingId) {
        Booking booking = bookingRepository.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));

        booking.setStatus(BookingStatus.CANCELLED);

        // Release booked slots
        if (booking.getConfirmedSlots() != null) {
            for (AvailabilitySlot slot : booking.getConfirmedSlots()) {
                slot.setBooked(false);
                slot.setBooking(null);
            }
            slotRepository.saveAll(booking.getConfirmedSlots());
        }

        bookingRepository.save(booking);
    }

    // ============= AVAILABILITY SLOTS =============

    public List<SlotResponse> getAvailableSlots(String subject, String grade) {
        // Finds everything except TRIAL (Regular, Evaluation, etc.)
        return slotRepository.findBySubjectAndGradeAndIsBookedFalseAndSessionTypeNot(subject, grade, SessionType.TRIAL)
                .stream()
                .map(this::mapSlotToResponse)
                .collect(Collectors.toList());
    }

    public List<SlotResponse> getAvailableTrialSlots(String subject, String grade) {
        // Finds ONLY TRIAL slots
        return slotRepository.findBySubjectAndGradeAndIsBookedFalseAndSessionType(subject, grade, SessionType.TRIAL)
                .stream()
                .map(this::mapSlotToResponse)
                .collect(Collectors.toList());
    }

    public List<SlotResponse> searchAvailableSlots(AvailableSlotSearchRequest request) {
        List<AvailabilitySlot> slots = slotRepository.findBySubjectAndGradeAndIsBookedFalse(
                request.getSubject(),
                request.getGrade()
        );

        // Filter by date range if provided
        if (request.getFromDate() != null || request.getToDate() != null) {
            slots = slots.stream()
                    .filter(slot -> {
                        boolean afterFrom = request.getFromDate() == null ||
                                !slot.getStartTime().isBefore(request.getFromDate());
                        boolean beforeTo = request.getToDate() == null ||
                                !slot.getStartTime().isAfter(request.getToDate());
                        return afterFrom && beforeTo;
                    })
                    .collect(Collectors.toList());
        }

        return slots.stream()
                .map(this::mapSlotToResponse)
                .collect(Collectors.toList());
    }

    // ============= STATISTICS =============

    public BookingSummaryResponse getBookingSummary() {
        List<Booking> allBookings = bookingRepository.findAll();

        return BookingSummaryResponse.builder()
                .totalBookings(allBookings.size())
                .pendingTrials(allBookings.stream()
                        .filter(b -> b instanceof TrialBooking && b.getStatus() == BookingStatus.PENDING)
                        .count())
                .confirmedBookings(allBookings.stream()
                        .filter(b -> b.getStatus() == BookingStatus.CONFIRMED)
                        .count())
                .completedBookings(allBookings.stream()
                        .filter(b -> b.getStatus() == BookingStatus.COMPLETED)
                        .count())
                .cancelledBookings(allBookings.stream()
                        .filter(b -> b.getStatus() == BookingStatus.CANCELLED)
                        .count())
                .build();
    }

    // ============= HELPER METHODS =============

    BookingResponse mapToResponse(Booking booking) {
        BookingResponse.BookingResponseBuilder builder = BookingResponse.builder()
                .id(booking.getId())
                .userId(booking.getUser().getId())
                .userFullName(booking.getUser().getFullName())
                .subject(booking.getSubject())
                .status(booking.getStatus())
                .createdAt(booking.getCreatedAt());

        if (booking.getConfirmedSlots() != null) {
            builder.confirmedSlots(booking.getConfirmedSlots().stream()
                    .map(this::mapSlotToResponse)
                    .collect(Collectors.toList()));
        }

        if (booking instanceof TrialBooking trial) {
            builder.bookingType("TRIAL")
                    .topicOfInterest(trial.getTopicOfInterest())
                    .preferredSlots(trial.getPreferredSlots())
                    .customRequest(trial.getCustomRequest());
        } else if (booking instanceof RegularBooking regular) {
            builder.bookingType("REGULAR")
                    .isPaid(regular.isPaid())
                    .lessonNumberInSeries(regular.getLessonNumberInSeries());
        }

        return builder.build();
    }

    private SlotResponse mapSlotToResponse(AvailabilitySlot slot) {
        return SlotResponse.builder()
                .id(slot.getId())
                .subject(slot.getSubject())
                .grade(slot.getGrade())
                .startTime(slot.getStartTime())
                .endTime(slot.getEndTime())
                .isBooked(slot.isBooked())
                .tutorName(slot.getTutorName())
                .sessionType(slot.getSessionType() != null ? slot.getSessionType().name() : null)
                .build();
    }
}
