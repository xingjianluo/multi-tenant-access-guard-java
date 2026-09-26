package com.github.xingjianluo.multitenantaccessguardjava.auth;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory refresh-token state with atomic rotation semantics.
 *
 * <p>Keyed by family id; each family record stores the id of its single currently
 * valid token. {@link #consume} is synchronized on the family record, so two
 * concurrent presentations of the same refresh token are serialized: the first one
 * rotates, the second one observes {@code used == true} (a replay) which revokes the
 * whole family. This guarantees concurrent renewal never produces a double release or
 * privilege escalation.
 */
@Component
public class InMemoryRefreshStore implements RefreshStore {

    /** Index from a token id to its family (covers all tokens ever minted in a family). */
    private final Map<String, String> tokenToFamily = new ConcurrentHashMap<>();
    private final Map<String, RefreshRecord> families = new ConcurrentHashMap<>();

    @Override
    public void save(RefreshRecord record) {
        tokenToFamily.put(record.tokenId(), record.familyId());
        families.put(record.familyId(), record);
    }

    @Override
    public RefreshVerdict consume(String tokenId, String nextTokenId, long nextExpiresAt, long nowMillis) {
        String familyId = tokenToFamily.get(tokenId);
        if (familyId == null) {
            return RefreshVerdict.reject(RefreshVerdict.Status.UNKNOWN,
                    com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason.INVALID_CREDENTIAL);
        }
        RefreshRecord current = families.get(familyId);
        if (current == null) {
            return RefreshVerdict.reject(RefreshVerdict.Status.UNKNOWN,
                    com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason.INVALID_CREDENTIAL);
        }
        synchronized (current) {
            // Re-read inside the monitor in case a concurrent consume already transitioned.
            current = families.get(familyId);
            if (current.revoked()) {
                return RefreshVerdict.reject(RefreshVerdict.Status.REVOKED,
                        com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason.CREDENTIAL_REVOKED);
            }
            if (!current.tokenId().equals(tokenId)) {
                // Presented token belongs to this family but is no longer the live token
                // (already rotated). That is a replay: revoke the whole family.
                RefreshRecord revoked = new RefreshRecord(current.familyId(), current.tokenId(),
                        current.tenantId(), current.subjectId(), current.loginEntry(),
                        current.expiresAt(), current.used(), true);
                families.put(familyId, revoked);
                return RefreshVerdict.reject(RefreshVerdict.Status.REPLAY,
                        com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason.CREDENTIAL_REPLAYED);
            }
            if (current.used()) {
                // Same live token presented a second time concurrently: replay again.
                RefreshRecord revoked = new RefreshRecord(current.familyId(), current.tokenId(),
                        current.tenantId(), current.subjectId(), current.loginEntry(),
                        current.expiresAt(), true, true);
                families.put(familyId, revoked);
                return RefreshVerdict.reject(RefreshVerdict.Status.REPLAY,
                        com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason.CREDENTIAL_REPLAYED);
            }
            if (current.expiresAt() <= nowMillis) {
                return RefreshVerdict.reject(RefreshVerdict.Status.REVOKED,
                        com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason.CREDENTIAL_EXPIRED);
            }
            // First presentation: atomically mark consumed and install the next live token.
            RefreshRecord rotated = new RefreshRecord(current.familyId(), nextTokenId,
                    current.tenantId(), current.subjectId(), current.loginEntry(),
                    nextExpiresAt, false, false);
            tokenToFamily.put(nextTokenId, familyId);
            families.put(familyId, rotated);
            RefreshRecord consumedView = new RefreshRecord(current.familyId(), tokenId,
                    current.tenantId(), current.subjectId(), current.loginEntry(),
                    current.expiresAt(), true, false);
            return RefreshVerdict.ok(consumedView);
        }
    }

    @Override
    public RefreshRecord findByFamily(String familyId) {
        return families.get(familyId);
    }
}
