package com.paulstna.springsecurityapp.security;

import com.paulstna.springsecurityapp.security.filter.JwtAuthenticationFilter;
import com.paulstna.springsecurityapp.security.filter.MdcFilter;
import com.paulstna.springsecurityapp.security.filter.RateLimiterFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    /**
     * The API documentation. Public on purpose: this is a demo deployment and
     * Swagger UI is its front door. Turn it off with
     * {@code springdoc.api-docs.enabled=false} and these paths stop existing.
     */
    private static final String[] API_DOCS = {
            "/v3/api-docs", "/v3/api-docs/**",
            "/swagger-ui.html", "/swagger-ui/**"
    };

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final RateLimiterFilter rateLimiterFilter;
    private final MdcFilter mdcFilter;
    private final RestAuthenticationEntryPoint authenticationEntryPoint;
    private final RestAccessDeniedHandler accessDeniedHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                                .requestMatchers(API_DOCS).permitAll()
                                .requestMatchers(HttpMethod.GET, "/api/v1/users", "/api/v1/users/**").hasRole("MANAGER")
                                .requestMatchers(HttpMethod.POST, "/api/v1/users").hasRole("ADMIN")
                                .requestMatchers(HttpMethod.PUT, "/api/v1/users/**").hasRole("MANAGER")
                                .requestMatchers(HttpMethod.DELETE, "/api/v1/users/**").hasRole("ADMIN")
                                .requestMatchers(
                                        "/api/v1/auth/register",
                                        "/api/v1/auth/refresh",
                                        "/api/v1/auth/login",
                                        "/api/v1/auth/logout").permitAll()
                                .anyRequest().authenticated()
                )
                // Without these, everything the filter chain rejects comes back as a
                // bodiless 403, whether the caller failed to authenticate or merely
                // lacks the role.
                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                // MdcFilter goes first so every request has a traceId, including
                // the ones the rate limiter turns away before anything else runs.
                .addFilterBefore(mdcFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(rateLimiterFilter, MdcFilter.class)
                .addFilterAfter(jwtAuthenticationFilter, RateLimiterFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("noop", NoOpPasswordEncoder.getInstance());
        encoders.put("bcrypt", new BCryptPasswordEncoder());
        return new DelegatingPasswordEncoder("bcrypt", encoders);
    }

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.withDefaultRolePrefix()
                .role("SYSTEM").implies("ADMIN")
                .role("ADMIN").implies("MANAGER")
                .role("MANAGER").implies("USER")
                .build();
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults("ROLE_");
    }

//    // if using pre-post method security also add
//    @Bean
//    static MethodSecurityExpressionHandler methodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
//        DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
//        expressionHandler.setRoleHierarchy(roleHierarchy);
//        return expressionHandler;
//    }
//

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
