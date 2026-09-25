package com.github.xingjianluo.multitenantaccessguardjava.auth;

import com.github.xingjianluo.multitenantaccessguardjava.model.LoginEntry;
import com.github.xingjianluo.multitenantaccessguardjava.model.Subject;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DefaultCredentialService implements CredentialService {

    @Override
    public Subject verifyPassword(String tenantId, String username, String password) {
        return null;
    }

    @Override
    public Subject verifySsoAssertion(String assertionId) {
        return null;
    }

    @Override
    public String issueSsoAssertion(String tenantId, String subjectId) {
        return null;
    }

    @Override
    public List<String> rolesOf(String tenantId, String subjectId) {
        return List.of();
    }

    @Override
    public void grantRole(String tenantId, String subjectId, String role) {
    }

    @Override
    public void revokeRole(String tenantId, String subjectId, String role) {
    }

    @Override
    public LoginEntry entryOf(String tenantId, String subjectId) {
        return null;
    }
}
