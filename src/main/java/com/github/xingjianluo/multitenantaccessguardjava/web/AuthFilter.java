package com.github.xingjianluo.multitenantaccessguardjava.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.multitenantaccessguardjava.auth.CredentialException;
import com.github.xingjianluo.multitenantaccessguardjava.auth.SessionService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.TokenService;
import com.github.xingjianluo.multitenantaccessguardjava.domain.AuthContext;
import com.github.xingjianluo.multitenantaccessguardjava.domain.DenyReason;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 统一认证过滤器：识别令牌入口（Authorization: Bearer）与会话入口（X-Session-Id）
 * 两种凭据，统一产出 AuthContext 挂到请求属性上，后续判定与入口无关。
 * 认证失败以可区分原因返回 401，不进入业务链路。
 */
@Component
public class AuthFilter extends OncePerRequestFilter {

    public static final String ATTR_AUTH_CONTEXT = "guard.authContext";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final TokenService tokenService;
    private final SessionService sessionService;

    public AuthFilter(TokenService tokenService, SessionService sessionService) {
        this.tokenService = tokenService;
        this.sessionService = sessionService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/api/auth/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String bearer = request.getHeader("Authorization");
        String sessionId = request.getHeader("X-Session-Id");
        try {
            AuthContext context = null;
            if (bearer != null && bearer.startsWith("Bearer ")) {
                context = tokenService.authenticate(bearer.substring(7));
            } else if (sessionId != null && !sessionId.isBlank()) {
                context = sessionService.authenticate(sessionId);
            }
            if (context != null) {
                request.setAttribute(ATTR_AUTH_CONTEXT, context);
            }
        } catch (CredentialException e) {
            reject(response, e.reason());
            return;
        }
        filterChain.doFilter(request, response);
    }

    private void reject(HttpServletResponse response, DenyReason reason) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "UNAUTHORIZED");
        body.put("reason", reason.name());
        response.getWriter().write(MAPPER.writeValueAsString(body));
    }
}
