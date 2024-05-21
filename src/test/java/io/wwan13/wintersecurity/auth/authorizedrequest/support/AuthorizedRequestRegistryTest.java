package io.wwan13.wintersecurity.auth.authorizedrequest.support;

import io.wwan13.wintersecurity.UnitTest;
import io.wwan13.wintersecurity.auth.authorizedrequest.AuthorizedRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizedRequestRegistryTest extends UnitTest {

    @Test
    void should_CreateAuthorizedRequest_when_UsingRegistry() {
        // given
        final String uriPattern = "/api/test/**";
        final HttpMethod httpMethod = HttpMethod.POST;
        final String role = "role";

        // when
        AuthorizedRequest authorizedRequest = AuthorizedRequestRegistry.of()
                .uriPatterns(uriPattern)
                .httpMethods(httpMethod)
                .hasRoles(role)
                .apply();

        // then
        assertThat(authorizedRequest).isInstanceOf(AuthorizedRequest.class);
    }
}