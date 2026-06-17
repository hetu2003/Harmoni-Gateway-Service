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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);

    @Value("${jwt.secret}")
    private String secretKey;

    private static final Set<String> PUBLIC_EXACT = Set.of(
            "/harmoni", "/harmoni/", "/harmoni/home",
            "/harmoni/login", "/harmoni/register",
            "/harmoni/logout",
            "/harmoni/forgot-password", "/harmoni/reset-password",
            "/harmoni/event", "/harmoni/event/search",
            "/harmoni/company",
            "/harmoni/profile", "/harmoni/profile/update",
            "/harmoni/about", "/harmoni/contact", "/harmoni/contact-submit",
            "/harmoni/faq", "/harmoni/privacy-policy", "/harmoni/closed-event",
            "/harmoni/get-city", "/harmoni/vendor/get-subcat",
            "/harmoni/home-search",
            "/harmoni/register-success",
            "/harmoni/feedback",
            "/harmoni/error"
    );

    private static final List<String> PUBLIC_PREFIX = List.of(
            "/harmoni/login/",
            "/harmoni/event-details/",
            "/harmoni/event-register/",
            "/harmoni/company/",
            "/harmoni/assets/",
            "/harmoni/uploads/",
            "/harmoni/location/",
            "/harmoni/payment/",
            "/auth/",
            "/harmoni/admin/"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String path = request.getRequestURI();

        if (isPublic(path)) {
            log.debug("[GATEWAY] PUBLIC  path={}", path);
            chain.doFilter(new HeaderAddingWrapper(request, null), response);
            return;
        }

        String jwt = extractCookie(request, "jwt_token");

        if (jwt == null) {
            log.warn("[GATEWAY] REDIRECT_LOGIN path={} reason=no_jwt_cookie", path);
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
            log.debug("[GATEWAY] PASS    path={} username={}", path, username);
            chain.doFilter(new HeaderAddingWrapper(request, username), response);

        } catch (Exception e) {
            log.warn("[GATEWAY] REDIRECT_LOGIN path={} reason=jwt_invalid error={}", path, e.getMessage());
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
            // Add ?expired=true so the login page knows this was a gateway-forced redirect
            // and can distinguish it from a user manually navigating to the login page
            response.sendRedirect(request.getContextPath() + "/harmoni/login?expired=true");
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
