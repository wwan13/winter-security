package io.wwan13.wintersecurity.auth;

import io.wwan13.wintersecurity.auth.provider.BearerTokenExtractor;

public class AuthTestContainer {

    public static TokenExtractor tokenExtractor = new BearerTokenExtractor();
}
