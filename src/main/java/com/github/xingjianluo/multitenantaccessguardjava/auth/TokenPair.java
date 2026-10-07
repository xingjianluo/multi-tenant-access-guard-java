package com.github.xingjianluo.multitenantaccessguardjava.auth;

/**
 * 登录签发的凭据对：平时访问用的 access 凭据 + 只能用于续期的 refresh 凭据。
 */
public record TokenPair(AuthToken accessToken, AuthToken refreshToken) {
}
