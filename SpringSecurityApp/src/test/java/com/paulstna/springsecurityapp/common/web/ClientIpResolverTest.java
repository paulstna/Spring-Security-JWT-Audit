package com.paulstna.springsecurityapp.common.web;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ClientIpResolver")
class ClientIpResolverTest {

    private ClientIpResolver resolver;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        resolver = new ClientIpResolver();
        request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1");
    }

    private void trustProxy(boolean trusted) {
        ReflectionTestUtils.setField(resolver, "trustProxy", trusted);
    }

    @Nested
    @DisplayName("when no proxy is trusted (the default)")
    class WithoutTrustedProxy {

        @BeforeEach
        void disableProxyTrust() {
            trustProxy(false);
        }

        @Test
        @DisplayName("uses the real socket address")
        void usesRemoteAddress() {
            assertThat(resolver.resolve(request)).isEqualTo("10.0.0.1");
        }

        @Test
        @DisplayName("ignores X-Forwarded-For, which any client can set freely")
        void ignoresForwardedFor() {
            request.addHeader("X-Forwarded-For", "203.0.113.7");

            assertThat(resolver.resolve(request))
                    .as("trusting this header would let a caller mint a new rate limit bucket per request")
                    .isEqualTo("10.0.0.1");
        }
    }

    @Nested
    @DisplayName("when running behind a trusted proxy")
    class WithTrustedProxy {

        @BeforeEach
        void enableProxyTrust() {
            trustProxy(true);
        }

        @Test
        @DisplayName("uses X-Forwarded-For when present")
        void prefersForwardedFor() {
            request.addHeader("X-Forwarded-For", "203.0.113.7");

            assertThat(resolver.resolve(request)).isEqualTo("203.0.113.7");
        }

        @Test
        @DisplayName("takes the left-most entry, which is the original client")
        void takesTheOriginalClientFromTheChain() {
            request.addHeader("X-Forwarded-For", "203.0.113.7, 70.41.3.18, 150.172.238.178");

            assertThat(resolver.resolve(request)).isEqualTo("203.0.113.7");
        }

        @Test
        @DisplayName("falls back to the socket address when the header is absent or blank")
        void fallsBackWhenHeaderIsUnusable() {
            assertThat(resolver.resolve(request)).isEqualTo("10.0.0.1");

            MockHttpServletRequest blank = new MockHttpServletRequest();
            blank.setRemoteAddr("10.0.0.2");
            blank.addHeader("X-Forwarded-For", "   ");

            assertThat(resolver.resolve(blank)).isEqualTo("10.0.0.2");
        }
    }
}
