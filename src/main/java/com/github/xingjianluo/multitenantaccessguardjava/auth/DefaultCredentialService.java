package com.github.xingjianluo.multitenantaccessguardjava.auth;

import com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.model.LoginEntry;
import com.github.xingjianluo.multitenantaccessguardjava.model.Subject;
import com.github.xingjianluo.multitenantaccessguardjava.support.AccessGuardException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory identity directory backing both login entries.
 *
 * <p>A password account and an SSO federation record may reference the same
 * (tenantId, subjectId); both resolve to an equal {@link Subject}, which is what makes
 * authorization results identical across the two entries. Passwords are stored as a
 * salted SHA-256 digest (demo-grade; no external crypto library required).
 *
 * <p>SSO assertions are single-use: they are removed atomically on first presentation,
 * so a captured/replayed assertion can never produce a second session.
 */
@Service
public class DefaultCredentialService implements CredentialService {

    private record Account(String tenantId, String username, String subjectId,
                           String salt, String passwordHash, List<String> roles) {
    }

    private record SsoRecord(String tenantId, String subjectId, long expiresAt) {
    }

    /** key = tenantId + "|" + username */
    private final Map<String, Account> accounts = new ConcurrentHashMap<>();
    /** key = assertionId */
    private final Map<String, SsoRecord> assertions = new ConcurrentHashMap<>();

    // ---- provisioning (used by the data initializer / tests) ----

    public void registerPasswordAccount(String tenantId, String username, String subjectId,
                                        String rawPassword, List<String> roles) {
        String salt = UUID.randomUUID().toString();
        accounts.put(accountKey(tenantId, username),
                new Account(tenantId, username, subjectId, salt, hash(rawPassword, salt),
                        new ArrayList<>(roles)));
    }

    @Override
    public String issueSsoAssertion(String tenantId, String subjectId) {
        String id = "sso-" + UUID.randomUUID();
        assertions.put(id, new SsoRecord(tenantId, subjectId, Long.MAX_VALUE));
        return id;
    }

    // ---- verification ----

    @Override
    public Subject verifyPassword(String tenantId, String username, String password) {
        Account account = accounts.get(accountKey(tenantId, username));
        if (account == null || !account.passwordHash().equals(hash(password, account.salt()))) {
            // Same reason whether the account is unknown or the password is wrong,
            // so callers cannot enumerate accounts.
            throw new AccessGuardException(DenyReason.BAD_CREDENTIALS, "invalid username or password");
        }
        return new Subject(account.tenantId(), account.subjectId(), LoginEntry.PASSWORD);
    }

    @Override
    public Subject verifySsoAssertion(String assertionId) {
        SsoRecord record = assertions.remove(assertionId);
        if (record == null) {
            throw new AccessGuardException(DenyReason.CREDENTIAL_REPLAYED,
                    "SSO assertion unknown or already consumed");
        }
        if (record.expiresAt() <= System.currentTimeMillis()) {
            throw new AccessGuardException(DenyReason.CREDENTIAL_EXPIRED, "SSO assertion expired");
        }
        return new Subject(record.tenantId(), record.subjectId(), LoginEntry.SSO);
    }

    // ---- roles ----

    @Override
    public List<String> rolesOf(String tenantId, String subjectId) {
        return accounts.values().stream()
                .filter(a -> a.tenantId().equals(tenantId) && a.subjectId().equals(subjectId))
                .map(Account::roles)
                .findFirst()
                .map(List::copyOf)
                .orElseGet(List::of);
    }

    @Override
    public synchronized void grantRole(String tenantId, String subjectId, String role) {
        accounts.values().stream()
                .filter(a -> a.tenantId().equals(tenantId) && a.subjectId().equals(subjectId))
                .findFirst()
                .ifPresent(a -> {
                    if (!a.roles().contains(role)) {
                        a.roles().add(role);
                    }
                });
    }

    @Override
    public synchronized void revokeRole(String tenantId, String subjectId, String role) {
        accounts.values().stream()
                .filter(a -> a.tenantId().equals(tenantId) && a.subjectId().equals(subjectId))
                .findFirst()
                .ifPresent(a -> a.roles().remove(role));
    }

    @Override
    public LoginEntry entryOf(String tenantId, String subjectId) {
        return LoginEntry.PASSWORD;
    }

    private static String accountKey(String tenantId, String username) {
        return tenantId + "|" + username;
    }

    private static String hash(String raw, String salt) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest((salt + ":" + raw).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : out) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
