package com.paulstna.springsecurityapp.audit.model;

import com.paulstna.springsecurityapp.user.repository.UserEntityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class SystemAuditorProvider {
    private final UserEntityRepository userRepository;
    private volatile UUID systemId;

    public UUID getSystemId() {
        if (systemId == null) {
            synchronized (this) {
                if (systemId == null) {
                    systemId = userRepository.findByUsername("SYSTEM")
                            .orElseThrow(() -> new IllegalStateException("SYSTEM user not found"))
                            .getId();
                }
            }
        }
        return systemId;
    }
}
