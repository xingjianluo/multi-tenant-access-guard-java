package com.github.xingjianluo.multitenantaccessguardjava.auth;

/**
 * 续期结果：轮换出的新访问凭据与新续期凭据（同一条续期链）。
 */
public record RenewalResult(AuthToken accessToken, AuthToken refreshToken) {
}
