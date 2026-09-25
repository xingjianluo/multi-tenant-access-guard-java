package com.github.xingjianluo.multitenantaccessguardjava.model;

/** Scope of a permission grant. */
public enum Scope {
    /** Permission applies to one specific resource. */
    RESOURCE,
    /** Permission applies to every resource in the subject's tenant. */
    TENANT
}
