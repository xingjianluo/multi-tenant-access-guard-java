package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditLog;
import com.github.xingjianluo.multitenantaccessguardjava.auth.AuthToken;
import com.github.xingjianluo.multitenantaccessguardjava.auth.SessionService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.TokenService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.UserDirectory;
import com.github.xingjianluo.multitenantaccessguardjava.domain.AccessDecision;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Action;
import com.github.xingjianluo.multitenantaccessguardjava.domain.AuthContext;
import com.github.xingjianluo.multitenantaccessguardjava.domain.GuardedResource;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Role;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Subject;
import com.github.xingjianluo.multitenantaccessguardjava.policy.AccessEvaluator;
import com.github.xingjianluo.multitenantaccessguardjava.policy.InMemoryPolicyStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 同一主体经令牌入口与会话入口访问同一资源，判定结论必须一致。 */
class EntryConsistencyTest {

    private static final Logger log = LoggerFactory.getLogger(EntryConsistencyTest.class);

    private TokenService tokens;
    private SessionService sessions;
    private AccessEvaluator evaluator;

    @BeforeEach
    void setUp() {
        MutableClock clock = new MutableClock(Instant.parse("2026-09-26T00:00:00Z"));
        UserDirectory directory = new UserDirectory();
        directory.register("alice", "pw", new Subject("u-alice", "tenant-a", Set.of(Role.USER)));
        tokens = new TokenService(directory, clock, 600, 3600, "test-secret");
        sessions = new SessionService(directory, clock, 600);
        InMemoryPolicyStore store = new InMemoryPolicyStore();
        store.registerResource(new GuardedResource("doc-1", "tenant-a", "u-alice"));
        store.registerResource(new GuardedResource("doc-2", "tenant-b", "u-bob"));
        evaluator = new AccessEvaluator(store, new AuditLog());
    }

    @Test
    void sameSubjectSameDecisionAcrossEntries() {
        AuthToken token = tokens.issue("u-alice", "tenant-a");
        String sessionId = sessions.createSession("u-alice", "tenant-a");
        AuthContext viaToken = tokens.authenticate(token.serialized());
        AuthContext viaSession = sessions.authenticate(sessionId);

        for (String resource : new String[]{"doc-1", "doc-2", "doc-x"}) {
            for (Action action : Action.values()) {
                AccessDecision a = evaluator.evaluate(viaToken, resource, action);
                AccessDecision b = evaluator.evaluate(viaSession, resource, action);
                log.info("TEST-ENTRY subject=u-alice tenant=tenant-a resource={} action={} token={}/{} session={}/{}",
                        resource, action, a.allowed(), a.denyReason(), b.allowed(), b.denyReason());
                assertEquals(a.allowed(), b.allowed(), resource + "/" + action + " 放行结论不一致");
                assertEquals(a.denyReason(), b.denyReason(), resource + "/" + action + " 拒绝原因不一致");
            }
        }
    }
}
