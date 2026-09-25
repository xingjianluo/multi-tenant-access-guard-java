package com.github.xingjianluo.multitenantaccessguardjava.web;

import com.github.xingjianluo.multitenantaccessguardjava.auth.AuthenticationService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Login entry endpoints. Both entries share the same response shape and resolve to
 * the same principal namespace; {@code entry} selects PASSWORD or SSO.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    public AuthController(AuthenticationService authenticationService) {
    }

    public record LoginRequest(String entry, String tenantId, String username,
                               String password, String assertionId) {
    }

    public record TokenResponse(String accessToken, String refreshToken, String tokenType, long expiresIn) {
    }

    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request) {
        return null;
    }

    public record RefreshRequest(String refreshToken) {
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody RefreshRequest request) {
        return null;
    }

    static Map<String, Object> stub() {
        return Map.of();
    }
}
