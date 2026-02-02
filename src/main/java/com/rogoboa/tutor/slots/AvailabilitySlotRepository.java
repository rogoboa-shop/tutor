package com.rogoboa.tutor.slots;

import com.rogoboa.tutor.SessionType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface AvailabilitySlotRepository extends JpaRepository<AvailabilitySlot, UUID> {

    // Find slots by Subject and Grade that are NOT yet booked
    List<AvailabilitySlot> findBySubjectAndGradeAndIsBookedFalse(String subject, String grade);

    /**
     * 1. Returns available TRIAL slots for a specific subject and grade.
     */
    List<AvailabilitySlot> findBySubjectAndGradeAndIsBookedFalseAndSessionType(
            String subject,
            String grade,
            SessionType sessionType
    );

    /**
     * 2. Returns available NON-TRIAL slots (Regular, Evaluation, etc.)
     * for a specific subject and grade.
     */
    List<AvailabilitySlot> findBySubjectAndGradeAndIsBookedFalseAndSessionTypeNot(
            String subject,
            String grade,
            SessionType sessionType
    );
}
