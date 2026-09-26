package com.github.xingjianluo.multitenantaccessguardjava.policy;

import com.github.xingjianluo.multitenantaccessguardjava.domain.Action;
import com.github.xingjianluo.multitenantaccessguardjava.domain.GuardedResource;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Role;
import org.springframework.stereotype.Component;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 基于 AtomicReference 的写时复制快照存储。
 * 每次变更在旧快照基础上构造完整新快照并原子替换：
 * - 进行中的请求复用其开始时取得的快照，判定结果在请求内一致；
 * - 变更对新请求立即整体生效，不会出现旧权限长期残留；
 * - 撤销与授予都以整体快照发布，不存在权限被短暂放大的中间态。
 */
@Component
public class InMemoryPolicyStore implements PolicyStore {

    private final AtomicReference<PolicySnapshot> current =
            new AtomicReference<>(new PolicySnapshot(0, defaultPermissions(), Map.of()));

    private static Map<Role, Set<Action>> defaultPermissions() {
        Map<Role, Set<Action>> map = new HashMap<>();
        map.put(Role.ADMIN, EnumSet.of(Action.READ, Action.WRITE, Action.DELETE));
        map.put(Role.USER, EnumSet.of(Action.READ, Action.WRITE));
        map.put(Role.VIEWER, EnumSet.of(Action.READ));
        return map;
    }

    @Override
    public PolicySnapshot current() {
        return current.get();
    }

    @Override
    public void grant(Role role, Action action) {
        mutate(role, action, true);
    }

    @Override
    public void revoke(Role role, Action action) {
        mutate(role, action, false);
    }

    private void mutate(Role role, Action action, boolean add) {
        current.updateAndGet(snapshot -> {
            Map<Role, Set<Action>> permissions = copyPermissions(snapshot);
            Set<Action> actions = EnumSet.noneOf(Action.class);
            actions.addAll(permissions.getOrDefault(role, Set.of()));
            if (add) {
                actions.add(action);
            } else {
                actions.remove(action);
            }
            permissions.put(role, actions);
            return new PolicySnapshot(snapshot.version() + 1, permissions, snapshot.resources());
        });
    }

    @Override
    public void setRolePermissions(Role role, Set<Action> actions) {
        current.updateAndGet(snapshot -> {
            Map<Role, Set<Action>> permissions = copyPermissions(snapshot);
            permissions.put(role, actions.isEmpty()
                    ? Set.of() : EnumSet.copyOf(actions));
            return new PolicySnapshot(snapshot.version() + 1, permissions, snapshot.resources());
        });
    }

    @Override
    public void registerResource(GuardedResource resource) {
        current.updateAndGet(snapshot -> {
            Map<String, GuardedResource> resources = new HashMap<>(snapshot.resources());
            resources.put(resource.resourceId(), resource);
            return new PolicySnapshot(snapshot.version() + 1, snapshot.rolePermissions(), resources);
        });
    }

    @Override
    public void removeResource(String resourceId) {
        current.updateAndGet(snapshot -> {
            Map<String, GuardedResource> resources = new HashMap<>(snapshot.resources());
            resources.remove(resourceId);
            return new PolicySnapshot(snapshot.version() + 1, snapshot.rolePermissions(), resources);
        });
    }

    private static Map<Role, Set<Action>> copyPermissions(PolicySnapshot snapshot) {
        Map<Role, Set<Action>> copy = new HashMap<>();
        snapshot.rolePermissions().forEach((role, actions) ->
                copy.put(role, actions.isEmpty() ? Set.of() : EnumSet.copyOf(actions)));
        return copy;
    }
}
