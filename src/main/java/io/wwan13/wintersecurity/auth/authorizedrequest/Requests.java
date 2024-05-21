package io.wwan13.wintersecurity.auth.authorizedrequest;

import org.springframework.http.HttpMethod;
import org.springframework.util.AntPathMatcher;

import java.util.Set;

public record Requests(
        Set<HttpMethod> methods,
        String uriPattern
) {

    private static final AntPathMatcher antPathMatcher = new AntPathMatcher();

    public boolean isRegistered(HttpMethod httpMethod, String requestUri) {
        return antPathMatcher.match(uriPattern, requestUri) &&
                methods.contains(httpMethod);
    }
}
