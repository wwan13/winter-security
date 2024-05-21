package io.wwan13.wintersecurity.auth.authorizedrequest;

import org.springframework.http.HttpMethod;

import java.util.Map;

public record AuthorizedRequest(
        Map<Requests, Permissions> registered,
        boolean isElseRequestPermit
) {

    public boolean isAccessibleRequest(HttpMethod httpMethod, String requestUri, String role) {
        return registered.keySet().stream()
                .filter(requests -> requests.isRegistered(httpMethod, requestUri))
                .map(registered::get)
                .findFirst()
                .map(permissions -> permissions.canAccess(role))
                .orElse(isElseRequestPermit);
    }
}
