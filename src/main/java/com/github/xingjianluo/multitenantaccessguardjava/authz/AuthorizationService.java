package com.github.xingjianluo.multitenantaccessguardjava.authz;

import com.github.xingjianluo.multitenantaccessguardjava.model.Action;
import com.github.xingjianluo.multitenantaccessguardjava.model.Decision;
import com.github.xingjianluo.multitenantaccessguardjava.model.Subject;

/**
 * Role- and ownership-based authorization. Every evaluation consults exactly one
 * immutable permission snapshot and produces an explainable, audited decision.
 */
public interface AuthorizationService {

    /**
     * @param subject authenticated caller
     * @param tenantId tenant the caller is asking within (resource names are tenant-local)
     * @param resourceId target resource
     * @param action requested action
     */
    Decision authorize(Subject subject, String tenantId, String resourceId, Action action);
}
