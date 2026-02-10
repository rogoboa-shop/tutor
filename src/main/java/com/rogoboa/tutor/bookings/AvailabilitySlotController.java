package com.rogoboa.tutor.bookings;

import com.rogoboa.tutor.bookings.dtos.CreateSlotRequest;
import com.rogoboa.tutor.bookings.dtos.SlotResponse;
import com.rogoboa.tutor.bookings.dtos.UpdateSlotRequest;
import com.rogoboa.tutor.usermanagement.User;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/slots")
@RequiredArgsConstructor
public class AvailabilitySlotController {

    private final AvailabilitySlotService slotService;

    @PostMapping
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<SlotResponse> createSlot(
            @Valid @RequestBody CreateSlotRequest request,
            @AuthenticationPrincipal User user
    ) {
        UUID tutorId = user.getId();

        SlotResponse response = slotService.createSlot(request, tutorId);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }


    @PostMapping("/bulk")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<List<SlotResponse>> createBulkSlots(
            @Valid @RequestBody List<CreateSlotRequest> requests,
            @AuthenticationPrincipal User user
    ) {
        UUID tutorId = user.getId();

        List<SlotResponse> responses = slotService.createBulkSlots(requests, tutorId);
        return ResponseEntity.status(HttpStatus.CREATED).body(responses);
    }


    @GetMapping
    public ResponseEntity<List<SlotResponse>> getAllSlots() {
        List<SlotResponse> slots = slotService.getAllSlots();
        return ResponseEntity.ok(slots);
    }

    @GetMapping("/{slotId}")
    public ResponseEntity<SlotResponse> getSlotById(@PathVariable UUID slotId) {
        SlotResponse slot = slotService.getSlotById(slotId);
        return ResponseEntity.ok(slot);
    }

    @PutMapping("/{slotId}")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<SlotResponse> updateSlot(
            @PathVariable UUID slotId,
            @Valid @RequestBody UpdateSlotRequest request) {
        SlotResponse updated = slotService.updateSlot(slotId, request);
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping("/{slotId}")
    @PreAuthorize("hasAnyRole('TUTOR', 'ADMIN')")
    public ResponseEntity<Void> deleteSlot(@PathVariable UUID slotId) {
        slotService.deleteSlot(slotId);
        return ResponseEntity.noContent().build();
    }
}