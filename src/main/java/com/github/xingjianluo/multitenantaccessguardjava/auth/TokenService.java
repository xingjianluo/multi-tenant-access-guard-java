package com.github.xingjianluo.multitenantaccessguardjava.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.xingjianluo.multitenantaccessguardjava.auth.AuthToken.TokenType;
import com.github.xingjianluo.multitenantaccessguardjava.domain.AuthContext;
import com.github.xingjianluo.multitenantaccessguardjava.domain.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.domain.EntryType;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Subject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 令牌入口：HMAC-SHA256 签名令牌的签发、校验与续期。
 * - 签名不合法 → CREDENTIAL_TAMPERED；
 * - 超过有效期 → CREDENTIAL_EXPIRED；
 * - 令牌分 ACCESS / REFRESH 两类，互不通用的入口混用 → CREDENTIAL_TYPE_MISMATCH；
 * - 续期以链（family）组织：登录签发同链的访问+续期凭据，每次续期在同链上轮换；
 * - 续期后旧凭据一次性作废，再次提交 → CREDENTIAL_REPLAYED，
 *   并作废整条续期链上的其他凭据（重放视为泄露信号）；
 * - 并发续期通过原子占位保证只有一个成功，不重复放行；
 * - 令牌只承载身份，角色在认证时从 UserDirectory 实时加载，杜绝权限提升窗口。
 */
@Service
public class TokenService {

    /** 一次登录/续期产出的凭据对：访问凭据 + 续期凭据。 */
    public record TokenPair(AuthToken access, AuthToken refresh) {
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private final UserDirectory userDirectory;
    private final Clock clock;
    private final Duration ttl;
    private final Duration refreshTtl;
    private final byte[] secret;

    /** 已作废令牌 jti → 原过期时间（用于惰性清理）。 */
    private final ConcurrentHashMap<String, Instant> invalidated = new ConcurrentHashMap<>();
    /** 已作废续期链 fid → 清理时间（重放检测到时整条链作废）。 */
    private final ConcurrentHashMap<String, Instant> revokedFamilies = new ConcurrentHashMap<>();

    public TokenService(UserDirectory userDirectory,
                        Clock clock,
                        @Value("${guard.token.ttl-seconds:1800}") long ttlSeconds,
                        @Value("${guard.token.refresh-ttl-seconds:86400}") long refreshTtlSeconds,
                        @Value("${guard.token.secret:multi-tenant-guard-demo-secret}") String secret) {
        this.userDirectory = userDirectory;
        this.clock = clock;
        this.ttl = Duration.ofSeconds(ttlSeconds);
        this.refreshTtl = Duration.ofSeconds(refreshTtlSeconds);
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
    }

    /** 登录签发：同一条续期链上的访问凭据 + 续期凭据。 */
    public TokenPair issuePair(String userId, String tenantId) {
        String familyId = UUID.randomUUID().toString();
        return new TokenPair(
                issue(userId, tenantId, TokenType.ACCESS, familyId, ttl),
                issue(userId, tenantId, TokenType.REFRESH, familyId, refreshTtl));
    }

    /** 仅签发访问凭据（无续期能力）。 */
    public AuthToken issue(String userId, String tenantId) {
        return issue(userId, tenantId, TokenType.ACCESS, UUID.randomUUID().toString(), ttl);
    }

    private AuthToken issue(String userId, String tenantId, TokenType type,
                            String familyId, Duration lifetime) {
        Instant now = clock.instant();
        ObjectNode payload = MAPPER.createObjectNode();
        String jti = UUID.randomUUID().toString();
        payload.put("jti", jti);
        payload.put("sub", userId);
        payload.put("tenant", tenantId);
        payload.put("typ", type.name());
        payload.put("fid", familyId);
        payload.put("iat", now.getEpochSecond());
        payload.put("exp", now.plus(lifetime).getEpochSecond());
        String body = B64.encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8));
        String serialized = body + "." + B64.encodeToString(sign(body));
        return new AuthToken(jti, userId, tenantId, type, familyId,
                now, now.plus(lifetime), serialized);
    }

    /** 校验序列化访问令牌并生成统一认证上下文；续期凭据不能用于访问。 */
    public AuthContext authenticate(String serialized) {
        JsonNode payload = parseAndVerify(serialized);
        requireType(payload, TokenType.ACCESS);
        String jti = payload.get("jti").asText();
        checkNotRevoked(payload, jti);
        long exp = payload.get("exp").asLong();
        if (clock.instant().getEpochSecond() >= exp) {
            throw new CredentialException(DenyReason.CREDENTIAL_EXPIRED,
                    "token " + jti + " expired at " + exp);
        }
        return toContext(payload, jti);
    }

    /**
     * 续期：只接受续期凭据。旧凭据原子作废并在同一链上签发新凭据对。
     * 已作废凭据再次提交视为重放：整条续期链作废，链上其他凭据一并失效。
     * 并发续期时只有一个调用能成功占位，其余得到 CREDENTIAL_REPLAYED。
     */
    public TokenPair refresh(String serialized) {
        JsonNode payload = parseAndVerify(serialized);
        requireType(payload, TokenType.REFRESH);
        String jti = payload.get("jti").asText();
        String fid = payload.get("fid").asText();
        long exp = payload.get("exp").asLong();
        if (revokedFamilies.containsKey(fid)) {
            throw new CredentialException(DenyReason.CREDENTIAL_REPLAYED,
                    "refresh family " + fid + " has been revoked");
        }
        if (clock.instant().getEpochSecond() >= exp) {
            throw new CredentialException(DenyReason.CREDENTIAL_EXPIRED,
                    "token " + jti + " expired at " + exp);
        }
        purgeExpiredInvalidations();
        if (invalidated.putIfAbsent(jti, Instant.ofEpochSecond(exp)) != null) {
            // 重放检测：旧凭据被再次提交，作废整条续期链
            revokedFamilies.put(fid, clock.instant().plus(refreshTtl));
            throw new CredentialException(DenyReason.CREDENTIAL_REPLAYED,
                    "token " + jti + " already rotated, family " + fid + " revoked");
        }
        String userId = payload.get("sub").asText();
        String tenantId = payload.get("tenant").asText();
        return new TokenPair(
                issue(userId, tenantId, TokenType.ACCESS, fid, ttl),
                issue(userId, tenantId, TokenType.REFRESH, fid, refreshTtl));
    }

    private void requireType(JsonNode payload, TokenType expected) {
        TokenType actual = TokenType.valueOf(payload.get("typ").asText());
        if (actual != expected) {
            throw new CredentialException(DenyReason.CREDENTIAL_TYPE_MISMATCH,
                    "token type " + actual + " cannot be used here, expected " + expected);
        }
    }

    private void checkNotRevoked(JsonNode payload, String jti) {
        if (invalidated.containsKey(jti)) {
            throw new CredentialException(DenyReason.CREDENTIAL_REPLAYED,
                    "token " + jti + " has been rotated");
        }
        String fid = payload.get("fid").asText();
        if (revokedFamilies.containsKey(fid)) {
            throw new CredentialException(DenyReason.CREDENTIAL_REPLAYED,
                    "refresh family " + fid + " has been revoked");
        }
    }

    private JsonNode parseAndVerify(String serialized) {
        try {
            int dot = serialized.lastIndexOf('.');
            if (dot <= 0) {
                throw new IllegalArgumentException("malformed");
            }
            String body = serialized.substring(0, dot);
            byte[] expected = sign(body);
            byte[] actual = B64D.decode(serialized.substring(dot + 1));
            if (!MessageDigest.isEqual(expected, actual)) {
                throw new IllegalArgumentException("bad signature");
            }
            JsonNode payload = MAPPER.readTree(B64D.decode(body));
            if (!payload.hasNonNull("jti") || !payload.hasNonNull("sub")
                    || !payload.hasNonNull("tenant") || !payload.hasNonNull("exp")
                    || !payload.hasNonNull("typ") || !payload.hasNonNull("fid")) {
                throw new IllegalArgumentException("missing claims");
            }
            return payload;
        } catch (CredentialException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialException(DenyReason.CREDENTIAL_TAMPERED,
                    "token failed signature/format verification");
        }
    }

    private AuthContext toContext(JsonNode payload, String jti) {
        String userId = payload.get("sub").asText();
        String tenantId = payload.get("tenant").asText();
        Subject subject = userDirectory.load(userId, tenantId)
                .orElseThrow(() -> new CredentialException(DenyReason.UNAUTHENTICATED,
                        "unknown subject " + userId + "@" + tenantId));
        return new AuthContext(subject, EntryType.TOKEN, jti);
    }

    private byte[] sign(String body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(body.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private void purgeExpiredInvalidations() {
        Instant now = clock.instant();
        invalidated.values().removeIf(exp -> exp.isBefore(now));
        revokedFamilies.values().removeIf(until -> until.isBefore(now));
    }
}
