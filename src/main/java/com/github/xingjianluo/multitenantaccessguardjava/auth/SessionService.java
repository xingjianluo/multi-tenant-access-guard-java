package com.github.xingjianluo.multitenantaccessguardjava.auth;

import com.github.xingjianluo.multitenantaccessguardjava.domain.AuthContext;
import com.github.xingjianluo.multitenantaccessguardjava.domain.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.domain.EntryType;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Subject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 会话入口：服务端会话的创建与校验。
 * 与令牌入口产出同一类 AuthContext（角色同样实时加载），保证两入口结论一致。
 */
@Service
public class SessionService {

    private record SessionEntry(String userId, String tenantId, Instant expiresAt) {
    }

    private final ConcurrentHashMap<String, SessionEntry> sessions = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    private final UserDirectory userDirectory;
    private final Clock clock;
    private final Duration ttl;

    public SessionService(UserDirectory userDirectory,
                          Clock clock,
                          @Value("${guard.session.ttl-seconds:1800}") long ttlSeconds) {
        this.userDirectory = userDirectory;
        this.clock = clock;
        this.ttl = Duration.ofSeconds(ttlSeconds);
    }

    public String createSession(String userId, String tenantId) {
        byte[] id = new byte[24];
        random.nextBytes(id);
        String sessionId = Base64.getUrlEncoder().withoutPadding().encodeToString(id);
        sessions.put(sessionId, new SessionEntry(userId, tenantId, clock.instant().plus(ttl)));
        return sessionId;
    }

    public AuthContext authenticate(String sessionId) {
        SessionEntry entry = sessions.get(sessionId);
        if (entry == null) {
            throw new CredentialException(DenyReason.UNAUTHENTICATED, "unknown session");
        }
        if (!clock.instant().isBefore(entry.expiresAt())) {
            sessions.remove(sessionId, entry);
            throw new CredentialException(DenyReason.CREDENTIAL_EXPIRED, "session expired");
        }
        Subject subject = userDirectory.load(entry.userId(), entry.tenantId())
                .orElseThrow(() -> new CredentialException(DenyReason.UNAUTHENTICATED,
                        "unknown subject " + entry.userId() + "@" + entry.tenantId()));
        return new AuthContext(subject, EntryType.SESSION, sessionId);
    }
}
