package com.rogoboa.tutor.usermanagement;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserContactRepository extends JpaRepository<UserContact, UUID> {
    List<UserContact> findByUserId(UUID userId);
    Optional<UserContact> findByVerificationToken(String token);
    boolean existsByUserIdAndTypeAndValue(UUID userId, ContactType type, String value);

    // Change this to match the property "primaryContact"
    Optional<UserContact> findByUserIdAndPrimaryContactTrue(UUID userId);
}
