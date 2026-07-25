package com.paulstna.springsecurityapp.auth.domain;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@Schema(description = "The access token. The refresh token is not in the body: it travels only "
        + "in an HttpOnly cookie, out of reach of JavaScript.")
public class AuthResponse {

    @Schema(description = "Signed JWT for the Authorization header. Valid for 15 minutes.",
            example = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjpbIlJPTEVfQURNSU4iXX0.MYPS8g")
    private String authToken;
}
