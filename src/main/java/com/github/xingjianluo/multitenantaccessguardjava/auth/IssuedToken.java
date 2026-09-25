package com.github.xingjianluo.multitenantaccessguardjava.auth;

/** An issued serialized token together with the claims inside it. */
public record IssuedToken(String token, TokenPayload payload) {
}
