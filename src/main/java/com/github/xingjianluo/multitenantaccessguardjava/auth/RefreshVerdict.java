package com.github.xingjianluo.multitenantaccessguardjava.auth;

import com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason;

/** Outcome of atomically consuming a refresh token. */
public record RefreshVerdict(Status status, RefreshRecord record, DenyReason denyReason) {

    public enum Status {
        /** First presentation of a live token; the caller may rotate. */
        OK,
        /** Token was already used once: replay, the whole family is revoked. */
        REPLAY,
        /** Token family had already been revoked. */
        REVOKED,
        /** No record for this token at all. */
        UNKNOWN
    }

    public static RefreshVerdict ok(RefreshRecord record) {
        return null;
    }

    public static RefreshVerdict reject(Status status, DenyReason reason) {
        return null;
    }
}
