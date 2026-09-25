package com.github.xingjianluo.multitenantaccessguardjava.model;

/**
 * An immutable permission grant: a role for a subject, scoped either to a single
 * resource or to the whole tenant.
 */
public record Permission(String tenantId,
                         String subjectId,
                         String role,
                         Scope scope,
                         String resourceId) {
}
