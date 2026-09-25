package com.github.xingjianluo.multitenantaccessguardjava.auth;

/**
 * Server-side record of a refresh token within a rotation family.
 *
 * @param familyId   rotation family; a replay revokes the entire family
 * @param tokenId    id of the current valid token of this family
 * @param tenantId   owning tenant
 * @param subjectId  owning subject
 * @param loginEntry entry point through which the original login happened
 * @param expiresAt  absolute expiry instant (millis)
 * @param used       whether this token has already been consumed once
 * @param revoked    whether the family has been revoked
 */
public record RefreshRecord(String familyId,
                            String tokenId,
                            String tenantId,
                            String subjectId,
                            com.github.xingjianluo.multitenantaccessguardjava.model.LoginEntry loginEntry,
                            long expiresAt,
                            boolean used,
                            boolean revoked) {
}
