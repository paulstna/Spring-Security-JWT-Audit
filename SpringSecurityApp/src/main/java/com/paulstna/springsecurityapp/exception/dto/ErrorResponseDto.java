package com.paulstna.springsecurityapp.exception.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
@Builder
@AllArgsConstructor
public class ErrorResponseDto {
    private Instant timestamp;
    private Integer status;
    private String message;
}
