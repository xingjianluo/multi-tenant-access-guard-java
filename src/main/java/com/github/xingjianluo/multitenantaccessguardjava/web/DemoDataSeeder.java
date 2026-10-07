package com.github.xingjianluo.multitenantaccessguardjava.web;

import com.github.xingjianluo.multitenantaccessguardjava.auth.UserDirectory;
import com.github.xingjianluo.multitenantaccessguardjava.domain.GuardedResource;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Role;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Subject;
import com.github.xingjianluo.multitenantaccessguardjava.policy.PolicyStore;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.util.Set;

/** 演示数据：两个租户、四类角色用户与若干资源，便于本地验证。 */
@Component
public class DemoDataSeeder {

    private final UserDirectory userDirectory;
    private final PolicyStore policyStore;

    public DemoDataSeeder(UserDirectory userDirectory, PolicyStore policyStore) {
        this.userDirectory = userDirectory;
        this.policyStore = policyStore;
    }

    @PostConstruct
    public void seed() {
        userDirectory.register("alice", "alice-pw",
                new Subject("u-alice", "tenant-a", Set.of(Role.USER)));
        userDirectory.register("carol", "carol-pw",
                new Subject("u-carol", "tenant-a", Set.of(Role.ADMIN)));
        userDirectory.register("dave", "dave-pw",
                new Subject("u-dave", "tenant-a", Set.of(Role.VIEWER)));
        // 专供敏感操作锁定端到端验证的 VIEWER，避免与登录锁定测试共享计数
        userDirectory.register("erin", "erin-pw",
                new Subject("u-erin", "tenant-a", Set.of(Role.VIEWER)));
        userDirectory.register("bob", "bob-pw",
                new Subject("u-bob", "tenant-b", Set.of(Role.USER)));

        policyStore.registerResource(new GuardedResource("doc-1", "tenant-a", "u-alice"));
        policyStore.registerResource(new GuardedResource("doc-2", "tenant-b", "u-bob"));
        // 同名资源在两个租户下各自独立存在、各自管理归属
        policyStore.registerResource(new GuardedResource("shared-doc", "tenant-a", "u-alice"));
        policyStore.registerResource(new GuardedResource("shared-doc", "tenant-b", "u-bob"));
    }
}
