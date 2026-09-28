package com.github.highcumontoa.tokenrotationaccesscontroljava.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.tokenrotationaccesscontroljava.auth.AccessControlService;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.AuthDecision;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.DenyReason;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.Permission;
import com.github.highcumontoa.tokenrotationaccesscontroljava.web.dto.ApiError;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.mvc.method.RequestMappingInfoHandlerMapping;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/**
 * Gate in front of every /api/** endpoint except the public auth endpoints. The required
 * permission is resolved from the handler method's {@link RequiredPermission} annotation (single
 * source of truth), so no controller code runs before the authorization decision. Denied requests
 * carry an explicit {@link DenyReason}, keeping the required cases apart:
 * <ul>
 *     <li>401 for unauthenticated / token-invalid / revoked credentials,</li>
 *     <li>403 ACCESS_DENIED for an authenticated identity lacking the permission.</li>
 * </ul>
 */
@Component
public class AuthorizationFilter extends OncePerRequestFilter {

    private static final Set<String> PUBLIC_PATHS = Set.of(
            "/api/auth/login", "/api/auth/refresh", "/api/auth/logout");

    private final AccessControlService accessControlService;
    private final ObjectMapper objectMapper;
    private final RequestMappingInfoHandlerMapping handlerMapping;

    public AuthorizationFilter(AccessControlService accessControlService, ObjectMapper objectMapper,
                               RequestMappingInfoHandlerMapping handlerMapping) {
        this.accessControlService = accessControlService;
        this.objectMapper = objectMapper;
        this.handlerMapping = handlerMapping;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/") || PUBLIC_PATHS.contains(path);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Permission required = resolveRequiredPermission(request);
        if (required == null) {
            writeError(response, HttpStatus.NOT_FOUND,
                    new AuthDecision.Denied(DenyReason.ACCESS_DENIED,
                            "no protected handler for " + request.getMethod() + " "
                                    + request.getRequestURI(), null));
            return;
        }

        AuthDecision decision = accessControlService.evaluate(request.getHeader("Authorization"), required);
        if (decision instanceof AuthDecision.Granted granted) {
            request.setAttribute(AuthenticatedUser.REQUEST_ATTRIBUTE,
                    new AuthenticatedUser(granted.username(), granted.sessionId(), granted.tokenId()));
            filterChain.doFilter(request, response);
            return;
        }

        AuthDecision.Denied denied = (AuthDecision.Denied) decision;
        writeError(response, statusFor(denied.reason()), denied);
    }

    private Permission resolveRequiredPermission(HttpServletRequest request) {
        try {
            HandlerExecutionChain chain = handlerMapping.getHandler(request);
            if (chain == null || !(chain.getHandler() instanceof HandlerMethod handlerMethod)) {
                return null;
            }
            if (handlerMethod.getBeanType().getName().startsWith("org.springframework")) {
                return null;
            }
            RequiredPermission annotation = handlerMethod.getMethodAnnotation(RequiredPermission.class);
            return annotation == null ? null : annotation.value();
        } catch (Exception e) {
            return null;
        }
    }

    static HttpStatus statusFor(DenyReason reason) {
        return reason == DenyReason.ACCESS_DENIED ? HttpStatus.FORBIDDEN : HttpStatus.UNAUTHORIZED;
    }

    private void writeError(HttpServletResponse response, HttpStatus status, AuthDecision.Denied denied)
            throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        ApiError body = new ApiError(status.getReasonPhrase(), denied.reason().name(),
                denied.detail(), denied.tokenId());
        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
