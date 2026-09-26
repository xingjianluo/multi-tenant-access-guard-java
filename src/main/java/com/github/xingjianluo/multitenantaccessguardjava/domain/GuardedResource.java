package com.github.xingjianluo.multitenantaccessguardjava.domain;

/** 受保护资源：归属于某租户与某属主。 */
public record GuardedResource(String resourceId, String tenantId, String ownerId) {
}
