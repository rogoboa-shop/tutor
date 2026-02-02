package com.rogoboa.tutor.bookings;

import com.rogoboa.tutor.bookings.dtos.CreateSlotRequest;
import com.rogoboa.tutor.bookings.dtos.SlotResponse;
import com.rogoboa.tutor.bookings.dtos.UpdateSlotRequest;
import com.rogoboa.tutor.slots.AvailabilitySlot;
import com.rogoboa.tutor.slots.AvailabilitySlotRepository;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AvailabilitySlotService {

    private final AvailabilitySlotRepository slotRepository;

    @Transactional
    public SlotResponse createSlot(@Valid CreateSlotRequest request) {
        AvailabilitySlot slot = AvailabilitySlot.builder()
                .subject(request.getSubject())
                .grade(request.getGrade())
                .startTime(request.getStartTime())
                .endTime(request.getEndTime())
                .tutorName(request.getTutorName())
                .sessionType(request.getSessionType())
                .isBooked(false)
                .build();

        AvailabilitySlot saved = slotRepository.save(slot);
        return mapToResponse(saved);
    }

    @Transactional
    public List<SlotResponse> createBulkSlots(List<CreateSlotRequest> requests) {
        List<AvailabilitySlot> slots = requests.stream()
                .map(request -> AvailabilitySlot.builder()
                        .subject(request.getSubject())
                        .grade(request.getGrade())
                        .startTime(request.getStartTime())
                        .endTime(request.getEndTime())
                        .tutorName(request.getTutorName())
                        .sessionType(request.getSessionType())
                        .isBooked(false)
                        .build())
                .collect(Collectors.toList());

        List<AvailabilitySlot> saved = slotRepository.saveAll(slots);
        return saved.stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    public List<SlotResponse> getAllSlots() {
        return slotRepository.findAll().stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    public SlotResponse getSlotById(UUID slotId) {
        AvailabilitySlot slot = slotRepository.findById(slotId)
                .orElseThrow(() -> new RuntimeException("Slot not found"));
        return mapToResponse(slot);
    }

    @Transactional
    public SlotResponse updateSlot(UUID slotId, @Valid UpdateSlotRequest request) {
        AvailabilitySlot slot = slotRepository.findById(slotId)
                .orElseThrow(() -> new RuntimeException("Slot not found"));

        if (request.getSubject() != null) {
            slot.setSubject(request.getSubject());
        }
        if (request.getGrade() != null) {
            slot.setGrade(request.getGrade());
        }
        if (request.getStartTime() != null) {
            slot.setStartTime(request.getStartTime());
        }
        if (request.getEndTime() != null) {
            slot.setEndTime(request.getEndTime());
        }
        if (request.getTutorName() != null) {
            slot.setTutorName(request.getTutorName());
        }
        if (request.getSessionType() != null) {
            slot.setSessionType(request.getSessionType());
        }

        AvailabilitySlot updated = slotRepository.save(slot);
        return mapToResponse(updated);
    }

    @Transactional
    public void deleteSlot(UUID slotId) {
        AvailabilitySlot slot = slotRepository.findById(slotId)
                .orElseThrow(() -> new RuntimeException("Slot not found"));

        if (slot.isBooked()) {
            throw new RuntimeException("Cannot delete a booked slot");
        }

        slotRepository.delete(slot);
    }

    private SlotResponse mapToResponse(AvailabilitySlot slot) {
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
