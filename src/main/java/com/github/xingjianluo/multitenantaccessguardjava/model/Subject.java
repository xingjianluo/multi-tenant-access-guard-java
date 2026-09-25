package com.github.xingjianluo.multitenantaccessguardjava.model;

/**
 * An authenticated identity. Identity is *only* (tenantId, subjectId); the
 * {@link LoginEntry} through which it was obtained is carried for audit but must
 * never change an authorization outcome.
 */
public record Subject(String tenantId, String subjectId, LoginEntry loginEntry) {
}
