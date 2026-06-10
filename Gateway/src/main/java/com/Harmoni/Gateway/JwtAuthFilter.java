package com.Harmoni.Gateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Value("${jwt.secret}")
    private String secretKey;

    private static final Set<String> PUBLIC_EXACT = Set.of(
            "/harmoni", "/harmoni/", "/harmoni/home",
            "/harmoni/login", "/harmoni/register",
            "/harmoni/forgot-password", "/harmoni/reset-password",
            "/harmoni/event", "/harmoni/event/search"
    );

    private static final List<String> PUBLIC_PREFIX = List.of(
            "/harmoni/login/",
            "/harmoni/event-details/",
            "/harmoni/company/",
            "/harmoni/assets/",
            "/harmoni/location/",
            "/auth/"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String path = request.getRequestURI();

        if (isPublic(path)) {
            chain.doFilter(request, response);
            return;
        }

        String jwt = extractCookie(request, "jwt_token");

        if (jwt == null) {
            redirectOrUnauthorized(request, response);
            return;
        }

        try {
            Claims claims = Jwts.parser()
                    .verifyWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .parseSignedClaims(jwt)
                    .getPayload();

            String username = claims.getSubject();
            chain.doFilter(new HeaderAddingWrapper(request, username), response);

        } catch (Exception e) {
            clearCookie(response, "jwt_token");
            redirectOrUnauthorized(request, response);
        }
    }

    private boolean isPublic(String path) {
        if (PUBLIC_EXACT.contains(path)) return true;
        return PUBLIC_PREFIX.stream().anyMatch(path::startsWith);
    }

    private String extractCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return null;
        for (Cookie c : request.getCookies()) {
            if (name.equals(c.getName())) return c.getValue();
        }
        return null;
    }

    private void redirectOrUnauthorized(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String accept = request.getHeader("Accept");
        if (accept != null && accept.contains("application/json")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        } else {
            response.sendRedirect(request.getContextPath() + "/harmoni/login");
        }
    }

    private void clearCookie(HttpServletResponse response, String name) {
        Cookie c = new Cookie(name, "");
        c.setMaxAge(0);
        c.setPath("/");
        response.addCookie(c);
    }

    /** Injects X-User-Name header into the proxied request */
    private static class HeaderAddingWrapper extends HttpServletRequestWrapper {
        private final String username;

        HeaderAddingWrapper(HttpServletRequest request, String username) {
            super(request);
            this.username = username;
        }

        @Override
        public String getHeader(String name) {
            if ("X-User-Name".equalsIgnoreCase(name)) return username;
            return super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            if ("X-User-Name".equalsIgnoreCase(name))
                return Collections.enumeration(List.of(username));
            return super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            List<String> names = Collections.list(super.getHeaderNames());
            if (!names.contains("X-User-Name")) names.add("X-User-Name");
            return Collections.enumeration(names);
        }
    }
}
