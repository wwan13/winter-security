/*
 * Copyright 2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.wwan13.wintersecurity.auth.authpattern;

import io.wwan13.wintersecurity.constant.DefaultAuthPattern;

import java.util.Optional;
import java.util.Set;

public record Permissions(
        Set<String> roles
) {

    public boolean canAccess(Set<String> enteredRoles) {
        return roles.stream()
                .anyMatch(role -> checkPermitAll(role) ||
                        checkAuthenticated(role, enteredRoles) || hasRole(role, enteredRoles));
    }

    private boolean checkPermitAll(String registeredRole) {
        return registeredRole.equals(DefaultAuthPattern.PERMIT_ALL);
    }

    private boolean checkAuthenticated(String registeredRole, Set<String> enteredRoles) {
        Optional<String> anonymousRole = enteredRoles.stream()
                .filter(DefaultAuthPattern.ANONYMOUS_ROLE::equals)
                .findAny();

        return registeredRole.equals(DefaultAuthPattern.AUTHENTICATED) &&
                anonymousRole.isEmpty();
    }

    private boolean hasRole(String registeredRole, Set<String> enteredRoles) {
        return enteredRoles.stream()
                .anyMatch(registeredRole::equals);
    }
}
