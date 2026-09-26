package com.github.xingjianluo.multitenantaccessguardjava.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.model.LoginEntry;
import com.github.xingjianluo.multitenantaccessguardjava.support.AccessGuardException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Compact HMAC-SHA256 signed tokens, implemented without a third-party JWT library.
 *
 * <p>Wire format: {@code base64url(payloadJson).base64url(hmac(payloadSegment))}.
 * Structural/signature failures are reported as {@link DenyReason#INVALID_CREDENTIAL}
 * (tampered); expiry is evaluated separately by the caller as
 * {@link DenyReason#CREDENTIAL_EXPIRED}, keeping the two rejection reasons distinct.
 */
@Service
public class HmacTokenService implements TokenService {

    private final byte[] secret;
    private final long accessTtlMillis;
    private final long refreshTtlMillis;
    private final ObjectMapper mapper = new ObjectMapper();

    public HmacTokenService(@Value("${guard.token.secret:local-dev-secret}") String secret,
                            @Value("${guard.token.access-ttl-millis:900000}") long accessTtlMillis,
                            @Value("${guard.token.refresh-ttl-millis:86400000}") long refreshTtlMillis) {
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
        this.accessTtlMillis = accessTtlMillis;
        this.refreshTtlMillis = refreshTtlMillis;
    }

    @Override
    public IssuedToken issueAccess(String tenantId, String subjectId, LoginEntry entry, String familyId, long nowMillis) {
        return issue(tenantId, subjectId, entry, familyId, TokenPayload.TYPE_ACCESS, accessTtlMillis, nowMillis);
    }

    @Override
    public IssuedToken issueRefresh(String tenantId, String subjectId, LoginEntry entry, String familyId, long nowMillis) {
        return issue(tenantId, subjectId, entry, familyId, TokenPayload.TYPE_REFRESH, refreshTtlMillis, nowMillis);
    }

    private IssuedToken issue(String tenantId, String subjectId, LoginEntry entry,
                              String familyId, String type, long ttl, long nowMillis) {
        TokenPayload payload = new TokenPayload(tenantId, subjectId, entry,
                UUID.randomUUID().toString(), familyId, nowMillis, nowMillis + ttl, type);
        String body = encode(toMap(payload));
        String sig = sign(body);
        return new IssuedToken(body + "." + sig, payload);
    }

    @Override
    public TokenPayload verifySignature(String serialized) {
        if (serialized == null) {
            throw new AccessGuardException(DenyReason.INVALID_CREDENTIAL, "missing credential");
        }
        int dot = serialized.lastIndexOf('.');
        if (dot <= 0 || dot == serialized.length() - 1) {
            throw new AccessGuardException(DenyReason.INVALID_CREDENTIAL, "malformed credential");
        }
        String body = serialized.substring(0, dot);
        String sig = serialized.substring(dot + 1);
        // constant-time comparison against the expected signature
        String expected = sign(body);
        if (!constantTimeEquals(expected, sig)) {
            throw new AccessGuardException(DenyReason.INVALID_CREDENTIAL, "credential signature mismatch");
        }
        try {
            Map<?, ?> map = mapper.readValue(Base64.getUrlDecoder().decode(body), Map.class);
            return new TokenPayload(
                    (String) map.get("tenantId"),
                    (String) map.get("subjectId"),
                    LoginEntry.valueOf((String) map.get("loginEntry")),
                    (String) map.get("tokenId"),
                    (String) map.get("familyId"),
                    ((Number) map.get("issuedAt")).longValue(),
                    ((Number) map.get("expiresAt")).longValue(),
                    (String) map.get("type"));
        } catch (Exception e) {
            throw new AccessGuardException(DenyReason.INVALID_CREDENTIAL, "credential payload unreadable");
        }
    }

    @Override
    public long accessTtlMillis() {
        return accessTtlMillis;
    }

    @Override
    public long refreshTtlMillis() {
        return refreshTtlMillis;
    }

    private String encode(Map<String, Object> map) {
        try {
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mapper.writeValueAsBytes(map));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String sign(String body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            byte[] raw = mac.doFinal(body.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private Map<String, Object> toMap(TokenPayload p) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("tenantId", p.tenantId());
        m.put("subjectId", p.subjectId());
        m.put("loginEntry", p.loginEntry().name());
        m.put("tokenId", p.tokenId());
        m.put("familyId", p.familyId());
        m.put("issuedAt", p.issuedAt());
        m.put("expiresAt", p.expiresAt());
        m.put("type", p.type());
        return m;
    }
}
