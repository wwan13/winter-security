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

package io.wwan13.wintersecurity.auth.provider;

import io.wwan13.wintersecurity.UnitTest;
import io.wwan13.wintersecurity.auth.authorizedrequest.AuthorizedRequest;
import io.wwan13.wintersecurity.auth.authorizedrequest.support.AuthorizedRequestApplier;
import io.wwan13.wintersecurity.auth.authorizedrequest.support.AuthorizedRequestRegistry;
import io.wwan13.wintersecurity.exception.forbidden.ForbiddenException;
import io.wwan13.wintersecurity.exception.unauthirized.UnauthorizedException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HttpRequestAccessManagerTest extends UnitTest {

    static AuthorizedRequest authorizedRequest = AuthorizedRequestApplier.apply(
            AuthorizedRequestRegistry.of()
                    .uriPatterns("/api/test")
                    .httpMethods(HttpMethod.POST, HttpMethod.GET)
                    .hasRoles("ROLE_USER")

                    .uriPatterns("api/hello")
                    .allHttpMethods()
                    .permitAll()
    );

    static HttpRequestAccessManager accessManager = new HttpRequestAccessManager(authorizedRequest);

    @Test
    void should_PassWithoutException_when_ValidRequestEnteredWithAuthentication() {
        // given
        final HttpMethod method = HttpMethod.POST;
        final String uri = "/api/test";
        final String role = "ROLE_USER";

        // when, then
        assertThatNoException()
                .isThrownBy(() -> accessManager.manageWithAuthentication(method, uri, role));
    }

    @Test
    void should_ThrowForbiddenException_when_InvalidRequestEnteredWithAuthentication() {
        // given
        final HttpMethod method = HttpMethod.POST;
        final String uri = "/api/test";
        final String role = "ROLE_ADMIN";

        // when, then
        assertThatThrownBy(() -> accessManager.manageWithAuthentication(method, uri, role))
                .isInstanceOf(ForbiddenException.class);
    }

    @Test
    void should_PassWithoutException_when_ValidRequestEnteredWithoutAuthentication() {
        // given
        final HttpMethod method = HttpMethod.GET;
        final String uri = "/api/hello";

        // when, then
        assertThatNoException()
                .isThrownBy(() -> accessManager.manageWithoutAuthentication(method, uri));
    }

    @Test
    void should_ThrowUnauthorizedException_when_InvalidRequestEnteredWithoutAuthentication() {
        // given
        final HttpMethod method = HttpMethod.POST;
        final String uri = "/api/test";

        // when, then
        assertThatThrownBy(() -> accessManager.manageWithoutAuthentication(method, uri))
                .isInstanceOf(UnauthorizedException.class);
    }
}