package io.wwan13.wintersecurity.auth.authorizedrequest.support;

import io.wwan13.wintersecurity.UnitTest;
import io.wwan13.wintersecurity.auth.authorizedrequest.AuthorizedRequest;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizedRequestApplierTest extends UnitTest {

    @Test
    void should_CreateAuthorizedRequest_when_RegistryEntered() {
        // given
        final AuthorizedRequestRegistry registry = AuthorizedRequestRegistry.of();
        registry
                .uriPatterns("/api/test")
                .allHttpMethods()
                .permitAll()
                .elseRequestPermit();

        // when
        AuthorizedRequest authorizedRequest = AuthorizedRequestApplier.apply(registry);

        // then
        assertThat(authorizedRequest).isInstanceOf(AuthorizedRequest.class);
    }
}