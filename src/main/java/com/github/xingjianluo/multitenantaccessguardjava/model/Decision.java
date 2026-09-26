package com.github.xingjianluo.multitenantaccessguardjava.model;

/**
 * Result of an authorization evaluation.
 *
 * @param allowed       whether access is allowed
 * @param reason        deny reason when {@code allowed == false}; {@code null} on allow
 * @param basis         human-readable explanation of the rule that produced the result
 * @param snapshotVersion the permission snapshot version consulted
 */
public record Decision(boolean allowed,
                       DenyReason reason,
                       String basis,
                       long snapshotVersion) {

    public static Decision allow(String basis, long snapshotVersion) {
        return new Decision(true, null, basis, snapshotVersion);
    }

    public static Decision deny(DenyReason reason, String basis, long snapshotVersion) {
        return new Decision(false, reason, basis, snapshotVersion);
    }
}
