package com.rogoboa.tutor.bookings;

import com.rogoboa.tutor.bookings.trial.TrialBooking;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface BookingRepository extends JpaRepository<Booking, UUID> {
    // Finds all bookings (Trials AND Regular) for a specific user
    List<Booking> findByUserId(UUID userId);

    // If you only want trials to show in an admin "Pending Trials" list
    @Query("SELECT t FROM TrialBooking t WHERE t.status = 'PENDING'")
    List<TrialBooking> findAllPendingTrials();
}
