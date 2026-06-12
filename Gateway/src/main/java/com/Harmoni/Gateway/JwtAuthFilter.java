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
            chain.doFilter(new HeaderAddingWrapper(request, null), response);
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

    /**
     * Injects X-Forwarded-* headers so Master knows the real client-facing host/port
     * (the Gateway at 8080), and optionally injects X-User-Name for authenticated requests.
     */
    private static class HeaderAddingWrapper extends HttpServletRequestWrapper {
        private final Map<String, String> extras = new LinkedHashMap<>();

        HeaderAddingWrapper(HttpServletRequest request, String username) {
            super(request);
            // Tell backend the original scheme/host/port the client used
            extras.put("X-Forwarded-Proto", request.getScheme());
            extras.put("X-Forwarded-Host",  request.getServerName());
            extras.put("X-Forwarded-Port",  String.valueOf(request.getServerPort()));
            extras.put("X-Forwarded-For",   request.getRemoteAddr());
            // Only added for authenticated requests
            if (username != null) extras.put("X-User-Name", username);
        }

        @Override
        public String getHeader(String name) {
            for (Map.Entry<String, String> e : extras.entrySet())
                if (e.getKey().equalsIgnoreCase(name)) return e.getValue();
            return super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            for (Map.Entry<String, String> e : extras.entrySet())
                if (e.getKey().equalsIgnoreCase(name))
                    return Collections.enumeration(List.of(e.getValue()));
            return super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            List<String> names = new ArrayList<>(Collections.list(super.getHeaderNames()));
            extras.keySet().forEach(k -> {
                if (names.stream().noneMatch(k::equalsIgnoreCase)) names.add(k);
            });
            return Collections.enumeration(names);
        }
    }
}
