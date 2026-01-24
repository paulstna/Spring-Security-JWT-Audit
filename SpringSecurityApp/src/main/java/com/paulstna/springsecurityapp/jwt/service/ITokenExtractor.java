package com.paulstna.springsecurityapp.jwt.service;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

public interface ITokenExtractor {
    Optional<String> extractFromRequest(HttpServletRequest request);
}
