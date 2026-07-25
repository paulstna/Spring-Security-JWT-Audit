package com.paulstna.springsecurityapp.common.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * OpenAPI document for the API.
 * <p>
 * The two credentials this API uses are declared as separate schemes because
 * they are genuinely different: the access token is a bearer header the caller
 * holds, the refresh token is an {@code HttpOnly} cookie the caller never sees
 * and the browser sends on its own.
 */
@Configuration
public class OpenApiConfig {

    public static final String BEARER_SCHEME = "bearerAuth";
    public static final String REFRESH_COOKIE_SCHEME = "refreshCookie";

    @Bean
    public OpenAPI apiDocumentation() {
        return new OpenAPI()
                .info(info())
                .servers(List.of(new Server()
                        .url("/")
                        .description("This server")))
                .components(new Components()
                        .addSecuritySchemes(BEARER_SCHEME, bearerScheme())
                        .addSecuritySchemes(REFRESH_COOKIE_SCHEME, refreshCookieScheme()));
    }

    private Info info() {
        return new Info()
                .title("Spring Security JWT Audit API")
                .version("v1")
                .description("""
                        REST API secured with JWT: a short-lived access token in the \
                        `Authorization` header and a long-lived refresh token in an \
                        `HttpOnly` cookie, rotated on every use.

                        **Authenticating in this page**
                        1. Call `POST /api/v1/auth/login` with one of the demo accounts \
                        (`admin` / `manager` / `user`, password `Demo1234!`).
                        2. Copy `authToken` from the response.
                        3. Click **Authorize** and paste it. The token is valid for 15 minutes.

                        The refresh cookie is set by the browser and scoped to \
                        `/api/v1/auth`, so `POST /api/v1/auth/refresh` works from this page \
                        without pasting anything.

                        **Roles** are hierarchical: `SYSTEM` > `ADMIN` > `MANAGER` > `USER`. \
                        A role inherits every permission below it.

                        Authentication endpoints are rate limited per client IP and answer \
                        `429` with a `Retry-After` header once the limit is hit.""")
                .contact(new Contact().name("PaulStna").url("https://github.com/PaulStna"))
                .license(new License().name("MIT").url("https://opensource.org/licenses/MIT"));
    }

    private SecurityScheme bearerScheme() {
        return new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT")
                .description("Access token returned by `/auth/login`. Paste the raw token; "
                        + "the `Bearer ` prefix is added for you.");
    }

    private SecurityScheme refreshCookieScheme() {
        return new SecurityScheme()
                .type(SecurityScheme.Type.APIKEY)
                .in(SecurityScheme.In.COOKIE)
                .name("refreshToken")
                .description("Set by `/auth/login` and `/auth/register`. `HttpOnly`, so it "
                        + "cannot be read from JavaScript, and sent only to `/api/v1/auth`.");
    }
}
