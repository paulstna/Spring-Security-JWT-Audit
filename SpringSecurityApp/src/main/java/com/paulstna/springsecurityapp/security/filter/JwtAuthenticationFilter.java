package com.paulstna.springsecurityapp.security.filter;

import com.paulstna.springsecurityapp.audit.constants.MdcKeysConstants;
import com.paulstna.springsecurityapp.jwt.domain.TokenType;
import com.paulstna.springsecurityapp.jwt.service.IJwtProvider;
import com.paulstna.springsecurityapp.jwt.service.ITokenExtractor;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final IJwtProvider jwtProvider;
    private final ITokenExtractor tokenExtractor;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        Optional<String> token = tokenExtractor.extractFromRequest(request);
        if (token.isEmpty() || !jwtProvider.isJwtValid(token.get())) {
            filterChain.doFilter(request, response);
            return;
        }

        if (jwtProvider.extractTokenType(token.get()) != TokenType.ACCESS_TOKEN) {
            filterChain.doFilter(request, response);
            return;
        }

        String username = jwtProvider.extractUsername(token.get());
        if (username == null) {
            filterChain.doFilter(request, response);
            return;
        }
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if (!userDetails.isEnabled() || !userDetails.isAccountNonLocked()) {
            filterChain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());

        authentication.setDetails(
                new WebAuthenticationDetailsSource()
                        .buildDetails(request)
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // The filter that establishes the identity is the one that records it.
        // MdcFilter runs earlier, before there is a caller to name, and clears
        // the whole context when the request ends.
        MDC.put(MdcKeysConstants.USER, username);

        filterChain.doFilter(request, response);
    }
}
