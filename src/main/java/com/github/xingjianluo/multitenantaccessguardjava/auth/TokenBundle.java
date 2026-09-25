package com.github.xingjianluo.multitenantaccessguardjava.auth;

/** The two tokens returned by a successful login or refresh. */
public record TokenBundle(IssuedToken accessToken, IssuedToken refreshToken) {
}
