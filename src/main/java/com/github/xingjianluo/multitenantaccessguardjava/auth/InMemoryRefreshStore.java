package com.github.xingjianluo.multitenantaccessguardjava.auth;

import org.springframework.stereotype.Component;

@Component
public class InMemoryRefreshStore implements RefreshStore {

    @Override
    public void save(RefreshRecord record) {
    }

    @Override
    public RefreshVerdict consume(String tokenId, String nextTokenId, long nowMillis) {
        return null;
    }

    @Override
    public RefreshRecord findByFamily(String familyId) {
        return null;
    }
}
