package com.rogoboa.tutor.bookings;

import com.rogoboa.tutor.bookings.tutor.TutorBookingFilterRequest;
import com.rogoboa.tutor.slots.AvailabilitySlot;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class BookingSpecifications {

    public static Specification<Booking> filterBy(UUID tutorId, TutorBookingFilterRequest filter) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            // 1. Mandatory Tutor Filter
            predicates.add(cb.equal(root.get("tutor").get("id"), tutorId));

            // 2. Status Filter
            if (filter.getStatus() != null) {
                predicates.add(cb.equal(root.get("status"), filter.getStatus()));
            }

            // 3. Booking Type (TRIAL/REGULAR)
            if (filter.getBookingType() != null) {
                predicates.add(cb.equal(root.get("bookingClass"), filter.getBookingType()));
            }

            // 4. Subject
            if (filter.getSubject() != null && !filter.getSubject().isBlank()) {
                predicates.add(cb.equal(root.get("subject"), filter.getSubject()));
            }

            // 5. Date Range (Checks against slots)
            if (filter.getFromDate() != null || filter.getToDate() != null) {
                Join<Booking, AvailabilitySlot> slots = root.join("confirmedSlots");
                if (filter.getFromDate() != null) {
                    predicates.add(cb.greaterThanOrEqualTo(slots.get("startTime"), filter.getFromDate()));
                }
                if (filter.getToDate() != null) {
                    predicates.add(cb.lessThanOrEqualTo(slots.get("startTime"), filter.getToDate()));
                }
                query.distinct(true); // Ensure unique bookings if multiple slots match
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}