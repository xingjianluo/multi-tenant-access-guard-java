package com.github.xingjianluo.multitenantaccessguardjava.model;

import java.util.List;

/**
 * Immutable, versioned snapshot of the whole permission configuration.
 *
 * <p>Authorization always evaluates against exactly one snapshot. Updates install a
 * new snapshot by a single atomic reference swap with a monotonically increasing
 * version, giving a defined consistency semantics: decisions made under one request
 * all observe one version; after the swap every new decision observes the new
 * permissions. There is neither a long-lived stale cache window nor a mixed read.
 */
public record PermissionSnapshot(long version, List<Permission> permissions) {
}
