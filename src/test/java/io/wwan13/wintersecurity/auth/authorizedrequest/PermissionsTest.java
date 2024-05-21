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

package io.wwan13.wintersecurity.auth.authorizedrequest;

import io.wwan13.wintersecurity.UnitTest;
import io.wwan13.wintersecurity.constant.DefaultAuthPattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class PermissionsTest extends UnitTest {

    @Test
    void should_HaveRoles() {
        // given
        final String roleValue = "role";
        final Set<String> roles = Set.of(roleValue);

        // when
        Permissions permissions = new Permissions(roles);

        // then
        assertThat(permissions).isInstanceOf(Permissions.class);
        assertThat(permissions.roles()).contains(roleValue);
    }

    @ParameterizedTest
    @CsvSource({"role1, true", "role2, true", "role3, false", "ROLE_ANONYMOUS, false"})
    void should_AcceptOnlyRegisteredRoles_when_SomeRolesRegistered(
            final String enteredRole,
            final boolean expected
    ) {
        // given
        final String role1 = "role1";
        final String role2 = "role2";
        final Set<String> roles = Set.of(role1, role2);
        Permissions permissions = new Permissions(roles);

        // when
        boolean result = permissions.canAccess(enteredRole);

        // then
        assertThat(result).isEqualTo(expected);
    }

    @ParameterizedTest
    @CsvSource({"role1, true", "role2, true", "role3, true", "ROLE_ANONYMOUS, true"})
    void should_AcceptAll_when_RegisteredIsPermitAll(
            final String enteredRole,
            final boolean expected
    ) {
        // given
        final Set<String> roles = Set.of(DefaultAuthPattern.PERMIT_ALL);
        Permissions permissions = new Permissions(roles);

        // when
        boolean result = permissions.canAccess(enteredRole);

        // then
        assertThat(result).isEqualTo(expected);
    }

    @ParameterizedTest
    @CsvSource({"role1, true", "role2, true", "role3, true", "ROLE_ANONYMOUS, false"})
    void should_AcceptAllValidRolesWithoutAnonymous_when_RegisteredIsAuthenticated(
            final String enteredRole,
            final boolean expected
    ) {
        // given
        final Set<String> roles = Set.of(DefaultAuthPattern.AUTHENTICATED);
        Permissions permissions = new Permissions(roles);

        // when
        boolean result = permissions.canAccess(enteredRole);

        // then
        assertThat(result).isEqualTo(expected);
    }
}