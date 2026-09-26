package com.github.xingjianluo.multitenantaccessguardjava.auth;

import com.github.xingjianluo.multitenantaccessguardjava.domain.Subject;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 用户目录：校验用户名口令并返回主体信息（演示用内存实现）。
 * 角色始终从这里实时加载，令牌/会话只承载身份，
 * 避免凭据内固化角色导致权限变更后旧角色长期生效。
 */
@Component
public class UserDirectory {

    private final Map<String, String> passwordHashes = new ConcurrentHashMap<>();
    private final Map<String, Subject> byUsername = new ConcurrentHashMap<>();
    private final Map<String, Subject> byUserIdAndTenant = new ConcurrentHashMap<>();

    public Optional<Subject> verify(String username, String password) {
        String hash = passwordHashes.get(username);
        if (hash == null || !MessageDigest.isEqual(
                hash.getBytes(StandardCharsets.UTF_8),
                sha256(password).getBytes(StandardCharsets.UTF_8))) {
            return Optional.empty();
        }
        return Optional.ofNullable(byUsername.get(username));
    }

    public Optional<Subject> load(String userId, String tenantId) {
        return Optional.ofNullable(byUserIdAndTenant.get(userId + "@" + tenantId));
    }

    public void register(String username, String password, Subject subject) {
        passwordHashes.put(username, sha256(password));
        byUsername.put(username, subject);
        byUserIdAndTenant.put(subject.userId() + "@" + subject.tenantId(), subject);
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
