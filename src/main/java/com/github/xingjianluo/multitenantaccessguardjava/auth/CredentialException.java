package com.github.xingjianluo.multitenantaccessguardjava.auth;

import com.github.xingjianluo.multitenantaccessguardjava.domain.DenyReason;

/** 凭据校验失败，携带可区分原因。 */
public class CredentialException extends RuntimeException {

    private final DenyReason reason;

    public CredentialException(DenyReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public DenyReason reason() {
        return reason;
    }
}
