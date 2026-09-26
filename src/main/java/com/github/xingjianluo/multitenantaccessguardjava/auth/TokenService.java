package com.github.xingjianluo.multitenantaccessguardjava.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
 * - 续期后旧令牌一次性作废，再次使用 → CREDENTIAL_REPLAYED；
 * - 并发续期通过原子占位保证只有一个成功，不重复放行；
 * - 令牌只承载身份，角色在认证时从 UserDirectory 实时加载，杜绝权限提升窗口。
 */
@Service
public class TokenService {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private final UserDirectory userDirectory;
    private final Clock clock;
    private final Duration ttl;
    private final byte[] secret;

    /** 已作废令牌 jti → 原过期时间（用于惰性清理）。 */
    private final ConcurrentHashMap<String, Instant> invalidated = new ConcurrentHashMap<>();

    public TokenService(UserDirectory userDirectory,
                        Clock clock,
                        @Value("${guard.token.ttl-seconds:1800}") long ttlSeconds,
                        @Value("${guard.token.secret:multi-tenant-guard-demo-secret}") String secret) {
        this.userDirectory = userDirectory;
        this.clock = clock;
        this.ttl = Duration.ofSeconds(ttlSeconds);
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
    }

    public AuthToken issue(String userId, String tenantId) {
        Instant now = clock.instant();
        ObjectNode payload = MAPPER.createObjectNode();
        String jti = UUID.randomUUID().toString();
        payload.put("jti", jti);
        payload.put("sub", userId);
        payload.put("tenant", tenantId);
        payload.put("iat", now.getEpochSecond());
        payload.put("exp", now.plus(ttl).getEpochSecond());
        String body = B64.encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8));
        String serialized = body + "." + B64.encodeToString(sign(body));
        return new AuthToken(jti, userId, tenantId, now, now.plus(ttl), serialized);
    }

    /** 校验序列化令牌并生成统一认证上下文。 */
    public AuthContext authenticate(String serialized) {
        JsonNode payload = parseAndVerify(serialized);
        String jti = payload.get("jti").asText();
        if (invalidated.containsKey(jti)) {
            throw new CredentialException(DenyReason.CREDENTIAL_REPLAYED,
                    "token " + jti + " has been rotated");
        }
        long exp = payload.get("exp").asLong();
        if (clock.instant().getEpochSecond() >= exp) {
            throw new CredentialException(DenyReason.CREDENTIAL_EXPIRED,
                    "token " + jti + " expired at " + exp);
        }
        return toContext(payload, jti);
    }

    /**
     * 续期：旧令牌原子作废并签发新令牌。
     * 并发续期时只有一个调用能成功占位，其余得到 CREDENTIAL_REPLAYED。
     */
    public AuthToken refresh(String serialized) {
        JsonNode payload = parseAndVerify(serialized);
        String jti = payload.get("jti").asText();
        long exp = payload.get("exp").asLong();
        if (clock.instant().getEpochSecond() >= exp) {
            throw new CredentialException(DenyReason.CREDENTIAL_EXPIRED,
                    "token " + jti + " expired at " + exp);
        }
        purgeExpiredInvalidations();
        if (invalidated.putIfAbsent(jti, Instant.ofEpochSecond(exp)) != null) {
            throw new CredentialException(DenyReason.CREDENTIAL_REPLAYED,
                    "token " + jti + " already rotated");
        }
        return issue(payload.get("sub").asText(), payload.get("tenant").asText());
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
                    || !payload.hasNonNull("tenant") || !payload.hasNonNull("exp")) {
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
    }
}
