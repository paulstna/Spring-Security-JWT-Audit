package com.paulstna.springsecurityapp.openapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.paulstna.springsecurityapp.support.AbstractIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The published API contract.
 * <p>
 * These assertions are about the document being usable and honest, not about
 * wording: that the URLs in it are the URLs the API actually serves, that the
 * credential each endpoint needs is declared, and that nothing the DTOs were
 * written to hide reappears in the schema.
 */
@DisplayName("OpenAPI documentation")
class OpenApiDocumentationIT extends AbstractIntegrationTest {

    /** Committed next to the code so the contract is reviewable in a diff. */
    private static final Path EXPORTED_DOCUMENT = Path.of("..", "docs", "openapi.json");

    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .enable(SerializationFeature.INDENT_OUTPUT);

    private JsonNode document;

    @BeforeEach
    void fetchDocument() throws Exception {
        document = JSON.readTree(mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"/v3/api-docs", "/swagger-ui/index.html"})
    @DisplayName("is readable without a token, or nobody could learn how to get one")
    void documentationIsPublic(String path) throws Exception {
        mockMvc.perform(get(path)).andExpect(status().isOk());
    }

    /**
     * Springdoc reads the mapping template literally and does not understand the
     * {@code version} attribute, so without a customizer every path would ship as
     * {@code /api/{version}/...} and "Try it out" would call a URL that does not exist.
     */
    @Test
    @DisplayName("documents the URLs the API actually serves, with the version resolved")
    void pathsAreConcrete() {
        assertThat(paths())
                .allSatisfy(path -> assertThat(path).startsWith("/api/v1/"))
                .contains("/api/v1/auth/login", "/api/v1/auth/refresh",
                        "/api/v1/users", "/api/v1/users/{id}");
    }

    @Test
    @DisplayName("declares both credentials, and describes the cookie as HttpOnly")
    void securitySchemesAreDeclared() {
        JsonNode schemes = document.at("/components/securitySchemes");

        assertThat(schemes.at("/bearerAuth/type").asText()).isEqualTo("http");
        assertThat(schemes.at("/bearerAuth/scheme").asText()).isEqualTo("bearer");
        assertThat(schemes.at("/bearerAuth/bearerFormat").asText()).isEqualTo("JWT");

        assertThat(schemes.at("/refreshCookie/in").asText()).isEqualTo("cookie");
        assertThat(schemes.at("/refreshCookie/name").asText()).isEqualTo("refreshToken");
        assertThat(schemes.at("/refreshCookie/description").asText()).contains("HttpOnly");
    }

    @ParameterizedTest(name = "{1} {0} needs {2}")
    @CsvSource({
            "/api/v1/users,          get,    bearerAuth",
            "/api/v1/users,          post,   bearerAuth",
            "/api/v1/users/{id},     put,    bearerAuth",
            "/api/v1/users/{id},     delete, bearerAuth",
            "/api/v1/auth/refresh,   post,   refreshCookie",
            "/api/v1/auth/logout,    post,   refreshCookie"
    })
    @DisplayName("states which credential each protected operation needs")
    void protectedOperationsDeclareTheirCredential(String path, String method, String scheme) {
        assertThat(security(path, method)).contains(scheme);
    }

    @ParameterizedTest(name = "{1} {0}")
    @CsvSource({"/api/v1/auth/login, post", "/api/v1/auth/register, post"})
    @DisplayName("asks for no credential where none is needed")
    void publicOperationsDeclareNoCredential(String path, String method) {
        assertThat(security(path, method)).isEmpty();
    }

    /**
     * The rate limiter is a filter, so nothing in the controllers would ever
     * mention it. The customizer reads the same properties the filter does.
     */
    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/refresh"})
    @DisplayName("warns that authentication endpoints are rate limited")
    void rateLimitedOperationsDocumentTheLimit(String path) {
        JsonNode tooManyRequests = document.at(quote(path) + "/post/responses/429");

        assertThat(tooManyRequests.isMissingNode()).isFalse();
        assertThat(tooManyRequests.at("/headers/Retry-After").isMissingNode())
                .as("a client cannot back off without being told for how long")
                .isFalse();
    }

    @Test
    @DisplayName("does not claim a rate limit on endpoints that have none")
    void unlimitedOperationsDocumentNoLimit() {
        assertThat(document.at("/paths/~1api~1v1~1users/get/responses/429").isMissingNode()).isTrue();
    }

    /** The DTOs exist to keep these out of responses; the contract must agree. */
    @Test
    @DisplayName("the user schema exposes no password and no tokens")
    void userSchemaLeaksNothing() {
        JsonNode properties = document.at("/components/schemas/UserResponse/properties");

        assertThat(properties.fieldNames()).toIterable()
                .containsExactlyInAnyOrder("id", "username", "roles",
                        "enabled", "accountNonLocked", "createdAt", "updatedAt");
    }

    @Test
    @DisplayName("every failure points at the one error shape")
    void failuresShareOneSchema() {
        List<String> withoutErrorSchema = new ArrayList<>();

        document.get("paths").properties().forEach(path ->
                path.getValue().properties().forEach(operation ->
                        operation.getValue().get("responses").properties().forEach(response -> {
                            if (Integer.parseInt(response.getKey()) < 400) {
                                return;
                            }
                            String ref = response.getValue()
                                    .at("/content/application~1json/schema/$ref").asText();
                            if (!ref.endsWith("/ErrorResponse")) {
                                withoutErrorSchema.add(
                                        operation.getKey() + " " + path.getKey() + " -> " + response.getKey());
                            }
                        })));

        assertThat(withoutErrorSchema).isEmpty();
    }

    /**
     * Regenerates the committed contract. Running {@code mvn verify} keeps it
     * current, so a change to the API shows up as a diff in review rather than
     * being noticed months later.
     */
    @Test
    @DisplayName("exports the contract to docs/openapi.json")
    void exportsTheContract() throws Exception {
        Files.createDirectories(EXPORTED_DOCUMENT.getParent());
        Files.writeString(EXPORTED_DOCUMENT, JSON.writeValueAsString(document) + System.lineSeparator());

        assertThat(EXPORTED_DOCUMENT).isNotEmptyFile();
    }

    private List<String> paths() {
        return new ArrayList<>(document.get("paths").propertyStream().map(java.util.Map.Entry::getKey).toList());
    }

    private List<String> security(String path, String method) {
        List<String> schemes = new ArrayList<>();
        document.at(quote(path) + "/" + method + "/security")
                .forEach(requirement -> requirement.fieldNames().forEachRemaining(schemes::add));
        return schemes;
    }

    /** JSON Pointer escaping: {@code /} becomes {@code ~1}. */
    private String quote(String path) {
        return "/paths/" + path.replace("~", "~0").replace("/", "~1");
    }
}
