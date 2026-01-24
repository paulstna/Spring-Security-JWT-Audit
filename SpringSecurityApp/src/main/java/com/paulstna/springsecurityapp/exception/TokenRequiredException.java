package com.paulstna.springsecurityapp.exception;


public class TokenRequiredException extends RuntimeException {
    public TokenRequiredException(String message) {
        super(message);
    }
}
