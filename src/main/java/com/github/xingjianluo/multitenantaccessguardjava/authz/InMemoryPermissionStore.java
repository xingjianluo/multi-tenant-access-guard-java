package com.github.xingjianluo.multitenantaccessguardjava.authz;

import com.github.xingjianluo.multitenantaccessguardjava.model.Permission;
import com.github.xingjianluo.multitenantaccessguardjava.model.PermissionSnapshot;
import com.github.xingjianluo.multitenantaccessguardjava.model.Resource;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * In-memory resource directory and versioned permission configuration.
 *
 * <p>Consistency semantics: {@link #current()} always returns one immutable
 * {@link PermissionSnapshot}. {@link #replacePermissions} builds the next immutable
 * snapshot and publishes it through a single {@link AtomicReference#set} with a
 * monotonically increasing version taken from an {@link AtomicLong}. Consequently:
 * <ul>
 *   <li>an in-flight decision reads one snapshot for its whole evaluation (no mixed
 *       reads / no brief privilege amplification window), and</li>
 *   <li>after the swap, every subsequent decision sees the new permissions (no
 *       long-lived stale cache).</li>
 * </ul>
 */
@Component
public class InMemoryPermissionStore implements PermissionStore {

    /** Composite key tenantId + "/" + resourceId. */
    private final Map<String, Resource> resources = new ConcurrentHashMap<>();
    private final AtomicReference<PermissionSnapshot> snapshot =
            new AtomicReference<>(new PermissionSnapshot(0L, List.of()));
    private final AtomicLong versions = new AtomicLong(0L);

    @Override
    public Resource findResource(String tenantId, String resourceId) {
        return resources.get(key(tenantId, resourceId));
    }

    @Override
    public void addResource(Resource resource) {
        resources.put(key(resource.tenantId(), resource.resourceId()), resource);
    }

    @Override
    public PermissionSnapshot current() {
        return snapshot.get();
    }

    @Override
    public void replacePermissions(List<Permission> permissions) {
        long nextVersion = versions.incrementAndGet();
        snapshot.set(new PermissionSnapshot(nextVersion, List.copyOf(permissions)));
    }

    private static String key(String tenantId, String resourceId) {
        return tenantId + "/" + resourceId;
    }
}
