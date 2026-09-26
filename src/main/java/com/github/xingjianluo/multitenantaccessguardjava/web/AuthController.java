package com.github.xingjianluo.multitenantaccessguardjava.web;

import com.github.xingjianluo.multitenantaccessguardjava.auth.AuthenticationService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.TokenBundle;
import com.github.xingjianluo.multitenantaccessguardjava.auth.TokenService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Login entry endpoints. {@code entry} is {@code PASSWORD} (username+password) or
 * {@code SSO} (single-use assertion). Both return the same token shape and converge on
 * the same principal, so access decisions are identical across entries.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationService authenticationService;
    private final TokenService tokenService;

    public AuthController(AuthenticationService authenticationService, TokenService tokenService) {
        this.authenticationService = authenticationService;
        this.tokenService = tokenService;
    }

    public record LoginRequest(String entry, String tenantId, String username,
                               String password, String assertionId) {
    }

    public record TokenResponse(String accessToken, String refreshToken,
                                String tokenType, long expiresIn) {
    }

    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request) {
        TokenBundle bundle = authenticationService.login(request.entry(), request.tenantId(),
                request.username(), request.password(), request.assertionId());
        return new TokenResponse(bundle.accessToken().token(), bundle.refreshToken().token(),
                "Bearer", tokenService.accessTtlMillis() / 1000);
    }

    public record RefreshRequest(String refreshToken) {
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody RefreshRequest request) {
        TokenBundle bundle = authenticationService.refresh(request.refreshToken());
        return new TokenResponse(bundle.accessToken().token(), bundle.refreshToken().token(),
                "Bearer", tokenService.accessTtlMillis() / 1000);
    }
}
