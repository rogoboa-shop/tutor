package com.rogoboa.tutor.bookings;

import com.rogoboa.tutor.bookings.trial.TrialBooking;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface BookingRepository extends JpaRepository<Booking, UUID>, JpaSpecificationExecutor<Booking> {

    // ============= USER QUERIES =============

    List<Booking> findByUserId(UUID userId);

    Page<Booking> findByUserId(UUID userId, Pageable pageable);

    long countByUserIdAndSubjectAndStatusIn(
            UUID userId,
            String subject,
            List<BookingStatus> statuses
    );

    @Query("SELECT t FROM TrialBooking t WHERE t.status = 'PENDING'")
    List<TrialBooking> findAllPendingTrials();

    // ============= TUTOR QUERIES =============
    // Direct query for tutor's own bookings
    Page<Booking> findByTutorId(UUID tutorId, Pageable pageable);

    // Filter by tutor and status
    Page<Booking> findByTutorIdAndStatus(UUID tutorId, BookingStatus status, Pageable pageable);

    // Query for "Other Tutors" (everyone except the current one)
    Page<Booking> findByTutorIdNot(UUID tutorId, Pageable pageable);

    // Missed bookings: Status is CONFIRMED but slots are in the past
    @Query("SELECT DISTINCT b FROM Booking b JOIN b.confirmedSlots s " +
            "WHERE b.tutor.id = :tutorId AND b.status = 'CONFIRMED' AND s.endTime < :now")
    Page<Booking> findMissedByTutorId(@Param("tutorId") UUID tutorId,
                                      @Param("now") LocalDateTime now,
                                      Pageable pageable);

    // Filter by Date Range (using the confirmed slots' start time)
    @Query("SELECT DISTINCT b FROM Booking b JOIN b.confirmedSlots s " +
            "WHERE b.tutor.id = :tutorId AND s.startTime >= :start AND s.startTime <= :end")
    Page<Booking> findByTutorIdAndDateRange(@Param("tutorId") UUID tutorId,
                                            @Param("start") LocalDateTime start,
                                            @Param("end") LocalDateTime end,
                                            Pageable pageable);

    //-----------Statistics---------
    // Add these to BookingRepository.java
    long countByTutorIdAndStatus(UUID tutorId, BookingStatus status);

    @Query("SELECT COUNT(DISTINCT b) FROM Booking b JOIN b.confirmedSlots s " +
            "WHERE b.tutor.id = :tutorId AND b.status = 'CONFIRMED' " +
            "AND s.startTime >= :start AND s.startTime <= :end")
    long countConfirmedInDateRange(@Param("tutorId") UUID tutorId,
                                   @Param("start") LocalDateTime start,
                                   @Param("end") LocalDateTime end);

}