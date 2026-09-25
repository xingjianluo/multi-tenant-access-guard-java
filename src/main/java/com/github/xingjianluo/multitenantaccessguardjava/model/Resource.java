package com.github.xingjianluo.multitenantaccessguardjava.model;

/** A protected resource owned by exactly one tenant. */
public record Resource(String tenantId, String resourceId, String ownerSubjectId) {
}
