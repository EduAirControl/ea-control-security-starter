package com.eduaircontrol.security.starter.jwt;

import java.util.List;
import java.util.UUID;

public record AuthenticatedUser(
        UUID userId,
        String email,
        String username,
        List<String> roles,
        UUID institutionId,
        UUID campusId) {
}