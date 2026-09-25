package com.github.xingjianluo.multitenantaccessguardjava.model;

/** The two coexisting login entry points. Both resolve to the same {@link Subject}. */
public enum LoginEntry {
    /** Username + password login. */
    PASSWORD,
    /** Federated single-sign-on assertion login. */
    SSO
}
