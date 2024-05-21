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
        final String role2 = "role3";
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