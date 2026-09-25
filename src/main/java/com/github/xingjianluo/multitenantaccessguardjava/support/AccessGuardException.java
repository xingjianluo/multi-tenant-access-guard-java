package com.github.xingjianluo.multitenantaccessguardjava.support;

import com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason;

/** Business/security exception carrying a distinguishable, externally safe deny reason. */
public class AccessGuardException extends RuntimeException {

    private final DenyReason reason;

    public AccessGuardException(DenyReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public DenyReason getReason() {
        return reason;
    }
}
