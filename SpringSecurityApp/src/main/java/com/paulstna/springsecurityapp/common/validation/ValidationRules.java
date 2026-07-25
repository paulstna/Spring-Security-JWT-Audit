package com.paulstna.springsecurityapp.common.validation;

import lombok.experimental.UtilityClass;

@UtilityClass
public class ValidationRules {

    public final int USERNAME_MIN = 3;
    public final int USERNAME_MAX = 50;

    public final int PASSWORD_MIN = 8;
    /**
     * BCrypt silently ignores anything past 72 bytes, so reject it up front.
     */
    public final int PASSWORD_MAX = 72;

    public final String USERNAME_PATTERN = "^[a-zA-Z0-9._-]+$";
    public final String USERNAME_MESSAGE =
            "Username may only contain letters, digits, dots, underscores and hyphens";

    public final String PASSWORD_PATTERN =
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^a-zA-Z0-9]).+$";
    public final String PASSWORD_MESSAGE =
            "Password must contain an uppercase letter, a lowercase letter, a digit and a special character";
}
