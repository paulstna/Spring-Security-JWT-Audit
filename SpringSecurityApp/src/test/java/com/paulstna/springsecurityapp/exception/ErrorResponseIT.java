package com.paulstna.springsecurityapp.exception;

import com.paulstna.springsecurityapp.support.AbstractIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Transactional
@DisplayName("Error responses")
class ErrorResponseIT extends AbstractIntegrationTest {

    @Test
    @DisplayName("every error carries a status, a path and the request's traceId")
    void errorsCarryContext() throws Exception {
        mockMvc.perform(get("/api/v1/users/11111111-1111-1111-1111-111111111111")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN))))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.message").value("User not found"))
                .andExpect(jsonPath("$.path").value("/api/v1/users/11111111-1111-1111-1111-111111111111"))
                .andExpect(jsonPath("$.traceId").isNotEmpty())
                .andExpect(jsonPath("$.timestamp").isNotEmpty());
    }

    /**
     * Regression: unmapped paths used to answer 403. The exception was forwarded to
     * /error, and on that dispatch the stateless filter chain saw an anonymous
     * request and denied it before the real status could surface.
     */
    @Test
    @DisplayName("an unmapped path is a 404, not a 403")
    void unmappedPathIsNotFound() throws Exception {
        mockMvc.perform(get("/api/v1/there-is-nothing-here")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN))))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.path").value("/api/v1/there-is-nothing-here"));
    }

    @Test
    @DisplayName("an unsupported method is a 405")
    void unsupportedMethodIsMethodNotAllowed() throws Exception {
        mockMvc.perform(patch("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN))))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(jsonPath("$.status").value(405));
    }

    @Test
    @DisplayName("a malformed JSON body is a 400")
    void malformedJsonIsBadRequest() throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\": broken"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    @DisplayName("an unparseable path variable is a 400")
    void badPathVariableIsBadRequest() throws Exception {
        mockMvc.perform(get("/api/v1/users/not-a-uuid")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    @DisplayName("an unsupported content type is a 415")
    void unsupportedMediaType() throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN)))
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("nope"))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(jsonPath("$.status").value(415));
    }

    @Test
    @DisplayName("no error body leaks a stack trace, class name or parser internals")
    void errorsRevealNoInternals() throws Exception {
        String[] bodies = {
                mockMvc.perform(get("/api/v1/there-is-nothing-here")
                                .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN))))
                        .andReturn().getResponse().getContentAsString(),
                mockMvc.perform(get("/api/v1/users/not-a-uuid")
                                .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN))))
                        .andReturn().getResponse().getContentAsString(),
                mockMvc.perform(post("/api/v1/users")
                                .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN)))
                                .contentType(MediaType.APPLICATION_JSON).content("{\"a\": "))
                        .andReturn().getResponse().getContentAsString()
        };

        for (String body : bodies) {
            assertThat(body)
                    .doesNotContain("Exception")
                    .doesNotContain("org.springframework")
                    .doesNotContain("java.lang")
                    .doesNotContain("com.paulstna");
        }
    }

    @Test
    @DisplayName("a duplicate username is a 409 with the offending name")
    void duplicateIsConflict() throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessTokenFor(ADMIN)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"admin","password":"Valid1234!"}"""))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.message").value("Username already exists: admin"));
    }
}
