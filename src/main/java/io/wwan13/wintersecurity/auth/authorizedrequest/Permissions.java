package io.wwan13.wintersecurity.auth.authorizedrequest;

import io.wwan13.wintersecurity.constant.DefaultAuthPattern;

import java.util.Set;

public record Permissions(
        Set<String> roles
) {

    public boolean canAccess(String enteredRole) {
        return roles.stream()
                .anyMatch(role -> checkPermitAll(role) ||
                        checkAuthenticated(role, enteredRole) || hasRole(role, enteredRole));
    }

    private boolean checkPermitAll(String registeredRole) {
        return registeredRole.equals(DefaultAuthPattern.PERMIT_ALL);
    }

    private boolean checkAuthenticated(String registeredRole, String enteredRole) {
        return registeredRole.equals(DefaultAuthPattern.AUTHENTICATED) &&
                !enteredRole.equals(DefaultAuthPattern.ANONYMOUS_ROLE);
    }

    private boolean hasRole(String registeredRole, String enteredRole) {
        return registeredRole.equals(enteredRole);
    }
}
