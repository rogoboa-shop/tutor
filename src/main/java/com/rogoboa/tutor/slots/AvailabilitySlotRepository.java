package com.rogoboa.tutor.slots;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface AvailabilitySlotRepository extends JpaRepository<AvailabilitySlot, UUID> {

    // Find slots by Subject and Grade that are NOT yet booked
    List<AvailabilitySlot> findBySubjectAndGradeAndIsBookedFalse(String subject, String grade);
}
