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
 * 令牌入口：HMAC-SHA256 签名凭据的签发、校验与续期。
 *
 * 凭据用途分离（收紧续期入口）：
 * - 登录签发一对凭据：access（typ=access，只能走业务入口）与
 *   refresh（typ=refresh，只能走 /api/auth/refresh）；
 * - 业务入口提交 refresh → CREDENTIAL_TYPE_MISMATCH；
 * - 续期入口提交 access → CREDENTIAL_NOT_REFRESHABLE；两类拒绝原因可区分。
 *
 * 续期链（chain）与重放防护：
 * - 每次登录生成一条续期链 chainId，access 与 refresh 都绑定该链；
 * - 续期即轮换 refresh：原子地把链头换成新 refresh，并签发新 access；
 *   并发续期在链状态上串行化，恰好只有一个成功，其余判定为 CREDENTIAL_REPLAYED；
 * - 紧邻上一代 refresh 的再次提交（含并发落败者）只拒绝、不作废，
 *   避免并发把胜出者刚拿到的新凭据误杀；
 * - 隔代/更老 refresh 的重放视为凭据被盗，整条链立即作废，
 *   链上尚未过期的 access 也一并拒绝（身份不会错认到别的租户/主体）；
 * - 凭据签名不合法 → CREDENTIAL_TAMPERED；超过有效期 → CREDENTIAL_EXPIRED；
 * - 角色仍在认证时从 UserDirectory 实时加载。
 */
@Service
public class TokenService {

    private static final String TYPE_ACCESS = "access";
    private static final String TYPE_REFRESH = "refresh";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    /** 一条续期链的服务端状态。所有变更都在实例监视器内串行完成。 */
    private static final class ChainState {
        private final String userId;
        private final String tenantId;
        private volatile String headRefreshJti;
        private volatile Instant headRefreshExp;
        private volatile boolean revoked;

        private ChainState(String userId, String tenantId, String headRefreshJti, Instant headRefreshExp) {
            this.userId = userId;
            this.tenantId = tenantId;
            this.headRefreshJti = headRefreshJti;
            this.headRefreshExp = headRefreshExp;
        }
    }

    /** 已消耗 refresh 到“下一代 refresh”的映射，用于区分紧邻重放与隔代重放。 */
    private record Consumed(String nextJti, Instant nextExp) {
    }

    private final UserDirectory userDirectory;
    private final Clock clock;
    private final Duration accessTtl;
    private final Duration refreshTtl;
    private final byte[] secret;

    private final ConcurrentHashMap<String, ChainState> chains = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Consumed> consumed = new ConcurrentHashMap<>();

    public TokenService(UserDirectory userDirectory,
                        Clock clock,
                        @Value("${guard.token.ttl-seconds:1800}") long accessTtlSeconds,
                        @Value("${guard.token.secret:multi-tenant-guard-demo-secret}") String secret) {
        this.userDirectory = userDirectory;
        this.clock = clock;
        this.accessTtl = Duration.ofSeconds(accessTtlSeconds);
        // 续期凭据寿命独立于访问凭据，默认更长。
        this.refreshTtl = Duration.ofSeconds(accessTtlSeconds * 2);
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
    }

    /** 登录签发：access + refresh 凭据对，共享一条新续期链。 */
    public TokenPair issuePair(String userId, String tenantId) {
        Instant now = clock.instant();
        String chainId = UUID.randomUUID().toString();
        AuthToken access = buildToken(userId, tenantId, chainId, TYPE_ACCESS, now, accessTtl);
        AuthToken refresh = buildToken(userId, tenantId, chainId, TYPE_REFRESH, now, refreshTtl);
        chains.put(chainId, new ChainState(userId, tenantId, refresh.tokenId(), refresh.expiresAt()));
        return new TokenPair(access, refresh);
    }

    private AuthToken buildToken(String userId, String tenantId, String chainId,
                                 String type, Instant now, Duration ttl) {
        Instant exp = now.plus(ttl);
        ObjectNode payload = MAPPER.createObjectNode();
        String jti = UUID.randomUUID().toString();
        payload.put("jti", jti);
        payload.put("sub", userId);
        payload.put("tenant", tenantId);
        payload.put("iat", now.getEpochSecond());
        payload.put("exp", exp.getEpochSecond());
        payload.put("typ", type);
        payload.put("chain", chainId);
        String body = B64.encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8));
        String serialized = body + "." + B64.encodeToString(sign(body));
        return new AuthToken(jti, userId, tenantId, now, exp, serialized);
    }

    /** 业务入口校验：只接受 access 凭据，并生成统一认证上下文。 */
    public AuthContext authenticate(String serialized) {
        JsonNode payload = parseAndVerify(serialized);
        String jti = payload.get("jti").asText();
        String type = payload.get("typ").asText();
        if (!TYPE_ACCESS.equals(type)) {
            throw new CredentialException(DenyReason.CREDENTIAL_TYPE_MISMATCH,
                    "refresh credential " + jti + " is not accepted at resource entry");
        }
        long exp = payload.get("exp").asLong();
        if (clock.instant().getEpochSecond() >= exp) {
            throw new CredentialException(DenyReason.CREDENTIAL_EXPIRED,
                    "token " + jti + " expired at " + exp);
        }
        ChainState chain = chains.get(payload.get("chain").asText());
        if (chain == null || chain.revoked) {
            throw new CredentialException(DenyReason.CREDENTIAL_REPLAYED,
                    "credential chain for " + jti + " is invalidated");
        }
        return toContext(payload, jti);
    }

    /**
     * 续期入口：只接受 refresh 凭据，原子轮换并返回新的一对凭据。
     * 并发续期恰好一个成功；紧邻重放只拒绝；隔代重放整条链作废。
     */
    public RenewalResult renew(String serialized) {
        JsonNode payload = parseAndVerify(serialized);
        String jti = payload.get("jti").asText();
        String type = payload.get("typ").asText();
        if (!TYPE_REFRESH.equals(type)) {
            throw new CredentialException(DenyReason.CREDENTIAL_NOT_REFRESHABLE,
                    "access credential " + jti + " cannot be used to renew");
        }
        long exp = payload.get("exp").asLong();
        if (clock.instant().getEpochSecond() >= exp) {
            throw new CredentialException(DenyReason.CREDENTIAL_EXPIRED,
                    "refresh " + jti + " expired at " + exp);
        }
        ChainState chain = chains.get(payload.get("chain").asText());
        if (chain == null) {
            throw new CredentialException(DenyReason.CREDENTIAL_REPLAYED,
                    "refresh " + jti + " belongs to an unknown chain");
        }
        purgeExpired();
        synchronized (chain) {
            if (chain.revoked) {
                throw new CredentialException(DenyReason.CREDENTIAL_REPLAYED,
                        "refresh " + jti + " rejected: chain revoked");
            }
            String head = chain.headRefreshJti;
            if (jti.equals(head)) {
                // 当前链头：唯一允许的续期。原子轮换到下一代。
                Instant now = clock.instant();
                AuthToken newAccess = buildToken(chain.userId, chain.tenantId,
                        payload.get("chain").asText(), TYPE_ACCESS, now, accessTtl);
                AuthToken newRefresh = buildToken(chain.userId, chain.tenantId,
                        payload.get("chain").asText(), TYPE_REFRESH, now, refreshTtl);
                consumed.put(head, new Consumed(newRefresh.tokenId(), newRefresh.expiresAt()));
                chain.headRefreshJti = newRefresh.tokenId();
                chain.headRefreshExp = newRefresh.expiresAt();
                return new RenewalResult(newAccess, newRefresh);
            }
            // 非链头：重放。紧邻上一代（含并发落败者）只拒绝，避免误杀胜出者；
            // 隔代或更老则判定为被盗，整条续期链立即作废。
            Consumed step = consumed.get(jti);
            boolean immediatePrevious = step != null && step.nextJti().equals(chain.headRefreshJti);
            if (!immediatePrevious) {
                chain.revoked = true;
            }
            throw new CredentialException(DenyReason.CREDENTIAL_REPLAYED,
                    immediatePrevious
                            ? "refresh " + jti + " already rotated (concurrent or immediate reuse)"
                            : "refresh " + jti + " is a stale replay; whole chain revoked");
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
                    || !payload.hasNonNull("typ") || !payload.hasNonNull("chain")) {
                throw new IllegalArgumentException("missing claims");
            }
            String typ = payload.get("typ").asText();
            if (!TYPE_ACCESS.equals(typ) && !TYPE_REFRESH.equals(typ)) {
                throw new IllegalArgumentException("unknown typ");
            }
            return payload;
        } catch (CredentialException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialException(DenyReason.CREDENTIAL_TAMPERED,
                    "credential failed signature/format verification");
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

    private void purgeExpired() {
        Instant now = clock.instant();
        consumed.values().removeIf(c -> c.nextExp().isBefore(now));
        chains.values().removeIf(c -> c.revoked
                && c.headRefreshExp != null && c.headRefreshExp.isBefore(now));
    }
}
