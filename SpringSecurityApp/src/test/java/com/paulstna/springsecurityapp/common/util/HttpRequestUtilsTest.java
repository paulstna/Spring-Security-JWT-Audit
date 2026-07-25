package com.paulstna.springsecurityapp.common.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("HttpRequestUtils")
class HttpRequestUtilsTest {

    /** The last path segment is what the rate limiter keys its buckets on. */
    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource({
            "/api/v1/auth/login,login",
            "/api/v1/auth/register,register",
            "/api/v1/auth/refresh,refresh",
            "/api/v1/auth/login/,login",
            "/api/v1/users,users",
            "/login,login"
    })
    @DisplayName("extracts the last path segment, ignoring a trailing slash")
    void extractsLastSegment(String uri, String expected) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(uri);

        assertThat(HttpRequestUtils.extractEndpoint(request)).isEqualTo(expected);
    }

    @ParameterizedTest(name = "a {0} path falls back to \"unknown\"")
    @CsvSource(value = {"empty,''", "null,NULL"}, nullValues = "NULL")
    @DisplayName("falls back to a safe value when there is no usable path")
    void fallsBackWhenPathIsUnusable(String description, String uri) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(uri);

        assertThat(HttpRequestUtils.extractEndpoint(request)).isEqualTo("unknown");
    }
}
