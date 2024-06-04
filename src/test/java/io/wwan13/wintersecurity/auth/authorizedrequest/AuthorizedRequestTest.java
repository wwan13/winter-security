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
import io.wwan13.wintersecurity.auth.authorizedrequest.support.AuthorizedRequestApplier;
import io.wwan13.wintersecurity.auth.authorizedrequest.support.AuthorizedRequestRegistry;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpMethod;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

class AuthorizedRequestTest extends UnitTest {

    @ParameterizedTest
    @CsvSource({
            "GET, /api/admin/member, ROLE_ADMIN, true",
            "PATCH, /api/admin/member, ROLE_ADMIN, false",
            "GET, /api/admin/member, ROLE_USER, false",
            "GET, /api/user/item, ROLE_USER, true",
            "GET, /api/super/item, ROLE_USER, false",
            "GET, /api/item/authenticated/test, ROLE_ANONYMOUS, false",
            "POST, /api/item/permit/test, ROLE_ANONYMOUS, true",
    })
    void should_JudgeRequestIsAccessible(
            final String requestMethod,
            final String requestUri,
            final String requestRole,
            final boolean expected
    ) {
        // given
        AuthorizedRequestRegistry registry = AuthorizedRequestRegistry.of();
        registry
                .uriPatterns("/api/admin/**")
                .httpMethods(GET, POST)
                .hasRoles("ROLE_ADMIN")

                .uriPatterns("/api/user/admin")
                .allHttpMethods()
                .hasRoles("ROLE_ADMIN")

                .uriPatterns("/api/user/**")
                .allHttpMethods()
                .hasRoles("ROLE_USER")

                .uriPatterns("/api/item/permit/**")
                .allHttpMethods()
                .permitAll()

                .uriPatterns("/api/item/authenticated/**")
                .allHttpMethods()
                .authenticated()

                .elseRequestAuthenticated();

        AuthorizedRequest authorizedRequest = AuthorizedRequestApplier.apply(registry);

        // when
        boolean result = authorizedRequest
                .isAccessibleRequest(HttpMethod.resolve(requestMethod), requestUri, Set.of(requestRole));

        // then
        assertThat(result).isEqualTo(expected);
    }

    @ParameterizedTest
    @CsvSource({
            "GET, /api/test, ROLE_ADMIN, true",
            "GET, /api/test, ROLE_USER, false",
            "GET, /api/any, ROLE_ADMIN, true",
            "GET, /api/any, ROLE_USER, true",
            "POST, /api/any, ROLE_USER, true",
    })
    void should_AcceptUnregisteredRequest_when_AnyRequestPermitAll(
            final String requestMethod,
            final String requestUri,
            final String requestRole,
            final boolean expected
    ) {
        // given
        AuthorizedRequestRegistry registry = AuthorizedRequestRegistry.of();
        registry
                .uriPatterns("/api/test")
                .httpMethods(GET)
                .hasRoles("ROLE_ADMIN")

                .elseRequestPermit();

        AuthorizedRequest authorizedRequest = AuthorizedRequestApplier.apply(registry);

        // when
        boolean result = authorizedRequest
                .isAccessibleRequest(HttpMethod.resolve(requestMethod), requestUri, Set.of(requestRole));

        // then
        assertThat(result).isEqualTo(expected);

    }

    @ParameterizedTest
    @CsvSource({
            "GET, /api/test, ROLE_ADMIN, true",
            "GET, /api/test, ROLE_USER, false",
            "GET, /api/any, ROLE_ADMIN, false",
            "GET, /api/any, ROLE_USER, false",
            "POST, /api/any, ROLE_USER, false",
    })
    void should_BlockUnregisteredRequest_when_AnyRequestAuthenticated(
            final String requestMethod,
            final String requestUri,
            final String requestRole,
            final boolean expected
    ) {
        // given
        AuthorizedRequestRegistry registry = AuthorizedRequestRegistry.of();
        registry
                .uriPatterns("/api/test")
                .httpMethods(GET)
                .hasRoles("ROLE_ADMIN")

                .elseRequestAuthenticated();

        AuthorizedRequest authorizedRequest = AuthorizedRequestApplier.apply(registry);

        // when
        boolean result = authorizedRequest
                .isAccessibleRequest(HttpMethod.resolve(requestMethod), requestUri, Set.of(requestRole));

        // then
        assertThat(result).isEqualTo(expected);
    }
}