package io.wwan13.wintersecurity.auth.authorizedrequest.support;

import io.wwan13.wintersecurity.auth.authorizedrequest.AuthorizedRequest;

public class AuthorizedRequestApplier {

    private AuthorizedRequestApplier() {
        throw new IllegalStateException("Cannot instantiate a utility class!");
    }

    public static AuthorizedRequest apply(AuthorizedRequestRegistry registry) {
        return registry.apply();
    }
}
