package com.rogoboa.tutor.slots;

import com.rogoboa.tutor.SessionType;
import com.rogoboa.tutor.bookings.BookingStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface AvailabilitySlotRepository extends JpaRepository<AvailabilitySlot, UUID> {

    // ============= EXISTING QUERIES =============

    List<AvailabilitySlot> findBySubjectAndGradeAndIsBookedFalse(String subject, String grade);

    List<AvailabilitySlot> findBySubjectAndGradeAndIsBookedFalseAndSessionType(
            String subject,
            String grade,
            SessionType sessionType
    );

    List<AvailabilitySlot> findBySubjectAndGradeAndIsBookedFalseAndSessionTypeNot(
            String subject,
            String grade,
            SessionType sessionType
    );

    // ============= TUTOR-FOCUSED QUERIES WITH BOOKING FETCH =============

    /**
     * Find all slots for a specific tutor with their bookings eagerly fetched.
     * This avoids N+1 queries by using JOIN FETCH.
     */
    @Query("""
            SELECT s FROM AvailabilitySlot s
            LEFT JOIN FETCH s.booking b
            LEFT JOIN FETCH b.user
            WHERE s.tutorName = :tutorName
              AND s.isBooked = true
            ORDER BY s.startTime DESC
            """)
    Page<AvailabilitySlot> findByTutorNameWithBookings(
            @Param("tutorName") String tutorName,
            Pageable pageable);

    /**
     * Find confirmed booking slots for a tutor.
     */
    @Query("""
            SELECT s FROM AvailabilitySlot s
            LEFT JOIN FETCH s.booking b
            LEFT JOIN FETCH b.user
            WHERE s.tutorName = :tutorName
              AND s.isBooked = true
              AND b.status = 'CONFIRMED'
            ORDER BY s.startTime DESC
            """)
    Page<AvailabilitySlot> findConfirmedByTutorName(
            @Param("tutorName") String tutorName,
            Pageable pageable);

    /**
     * Find cancelled booking slots for a tutor.
     */
    @Query("""
            SELECT s FROM AvailabilitySlot s
            LEFT JOIN FETCH s.booking b
            LEFT JOIN FETCH b.user
            WHERE s.tutorName = :tutorName
              AND s.isBooked = true
              AND b.status = 'CANCELLED'
            ORDER BY s.startTime DESC
            """)
    Page<AvailabilitySlot> findCancelledByTutorName(
            @Param("tutorName") String tutorName,
            Pageable pageable);

    /**
     * Find missed booking slots - confirmed but all slots have ended.
     */
    @Query("""
            SELECT s FROM AvailabilitySlot s
            LEFT JOIN FETCH s.booking b
            LEFT JOIN FETCH b.user
            WHERE s.tutorName = :tutorName
              AND s.isBooked = true
              AND b.status = 'CONFIRMED'
              AND s.endTime < :now
            ORDER BY s.startTime DESC
            """)
    Page<AvailabilitySlot> findMissedByTutorName(
            @Param("tutorName") String tutorName,
            @Param("now") LocalDateTime now,
            Pageable pageable);

    /**
     * Find slots by tutor and date range.
     */
    @Query("""
            SELECT s FROM AvailabilitySlot s
            LEFT JOIN FETCH s.booking b
            LEFT JOIN FETCH b.user
            WHERE s.tutorName = :tutorName
              AND s.isBooked = true
              AND s.startTime >= :fromDate
              AND s.endTime <= :toDate
            ORDER BY s.startTime DESC
            """)
    Page<AvailabilitySlot> findByTutorNameAndDateRange(
            @Param("tutorName") String tutorName,
            @Param("fromDate") LocalDateTime fromDate,
            @Param("toDate") LocalDateTime toDate,
            Pageable pageable);

    /**
     * Find other tutors' booked slots (not belonging to the specified tutor).
     */
    @Query("""
            SELECT s FROM AvailabilitySlot s
            LEFT JOIN FETCH s.booking b
            LEFT JOIN FETCH b.user
            WHERE s.tutorName != :tutorName
              AND s.isBooked = true
            ORDER BY s.startTime DESC
            """)
    Page<AvailabilitySlot> findByOtherTutors(
            @Param("tutorName") String tutorName,
            Pageable pageable);

    /**
     * Generic filtered query for tutor slots.
     * Fetches booking and user eagerly to avoid N+1.
     */
    @Query("""
            SELECT s FROM AvailabilitySlot s
            LEFT JOIN FETCH s.booking b
            LEFT JOIN FETCH b.user
            WHERE s.tutorName = :tutorName
              AND s.isBooked = true
              AND (:status IS NULL OR b.status = :status)
              AND (:bookingType IS NULL OR b.bookingClass = :bookingType)
              AND (:subject IS NULL OR s.subject = :subject)
              AND (:fromDate IS NULL OR s.startTime >= :fromDate)
              AND (:toDate IS NULL OR s.endTime <= :toDate)
            ORDER BY s.startTime DESC
            """)
    Page<AvailabilitySlot> findFilteredByTutorName(
            @Param("tutorName") String tutorName,
            @Param("status") BookingStatus status,
            @Param("bookingType") String bookingType,
            @Param("subject") String subject,
            @Param("fromDate") LocalDateTime fromDate,
            @Param("toDate") LocalDateTime toDate,
            Pageable pageable);

    /**
     * Get count queries for pagination - these don't need JOIN FETCH.
     */
    @Query("""
            SELECT COUNT(DISTINCT s.id) FROM AvailabilitySlot s
            WHERE s.tutorName = :tutorName
              AND s.isBooked = true
            """)
    long countByTutorName(@Param("tutorName") String tutorName);

    /**
     * Find all slots for a specific booking (useful for status updates).
     */
    @Query("""
            SELECT s FROM AvailabilitySlot s
            WHERE s.booking.id = :bookingId
            """)
    List<AvailabilitySlot> findByBookingId(@Param("bookingId") UUID bookingId);
}