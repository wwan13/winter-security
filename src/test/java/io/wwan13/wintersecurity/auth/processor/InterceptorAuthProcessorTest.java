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

package io.wwan13.wintersecurity.auth.processor;

import io.wwan13.wintersecurity.UnitTest;
import io.wwan13.wintersecurity.auth.AuthTestContainer;
import io.wwan13.wintersecurity.auth.RequestAccessManager;
import io.wwan13.wintersecurity.auth.authpattern.AuthPatterns;
import io.wwan13.wintersecurity.auth.authpattern.support.AuthPatternsApplier;
import io.wwan13.wintersecurity.auth.authpattern.support.AuthPatternsRegistry;
import io.wwan13.wintersecurity.auth.provider.HttpRequestAccessManager;
import io.wwan13.wintersecurity.auth.stub.StubHttpServletRequest;
import io.wwan13.wintersecurity.exception.forbidden.ForbiddenException;
import io.wwan13.wintersecurity.exception.unauthirized.UnauthorizedException;
import io.wwan13.wintersecurity.jwt.Payload;
import io.wwan13.wintersecurity.jwt.provider.ProviderTestContainer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpMethod;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InterceptorAuthProcessorTest extends UnitTest {

    static AuthPatterns authPatterns = AuthPatternsApplier.apply(
            AuthPatternsRegistry.of()
                    .uriPatterns("/api/user")
                    .httpMethods(HttpMethod.POST, HttpMethod.GET)
                    .hasRoles("ROLE_USER")

                    .uriPatterns("/api/admin")
                    .httpMethods(HttpMethod.POST, HttpMethod.GET)
                    .hasRoles("ROLE_ADMIN")

                    .uriPatterns("api/hello")
                    .allHttpMethods()
                    .permitAll()
    );

    static RequestAccessManager accessManager = new HttpRequestAccessManager(authPatterns);

    static InterceptorAuthProcessor interceptorAuthProcessor = new InterceptorAuthProcessor(
            AuthTestContainer.tokenExtractor,
            ProviderTestContainer.tokenDecoder,
            accessManager
    );

    @ParameterizedTest
    @CsvSource({
            "GET, /api/user, ROLE_USER",
            "GET, /api/admin, ROLE_ADMIN",
            "GET, /api/hello, ROLE_USER",
            "GET, /api/hello, ROLE_ADMIN",
    })
    void should_PassWithoutException_when_ValidRequestWithValidTokenEntered(
            final String method,
            final String uri,
            final String role
    ) {
        // given
        final StubHttpServletRequest request = new StubHttpServletRequest();
        request.getMethodWillReturn(method);
        request.getRequestUriWillReturn(uri);

        final Payload payload = new ProviderTestContainer.TestPayload(1, role, "claim");
        final String token = ProviderTestContainer.tokenGenerator.accessToken(payload);
        final String bearerToken = "Bearer " + token;
        request.getHeaderWillReturn(bearerToken);

        // when, then
        assertThatNoException()
                .isThrownBy(() -> interceptorAuthProcessor.process(request));
    }

    @ParameterizedTest
    @CsvSource({
            "GET, /api/user, ROLE_ADMIN",
            "GET, /api/admin, ROLE_USER"
    })
    void should_ThrowForbiddenException_when_InValidRequestWithValidTokenEntered(
            final String method,
            final String uri,
            final String role
    ) {
        // given
        final StubHttpServletRequest request = new StubHttpServletRequest();
        request.getMethodWillReturn(method);
        request.getRequestUriWillReturn(uri);

        final Payload payload = new ProviderTestContainer.TestPayload(1, role, "claim");
        final String token = ProviderTestContainer.tokenGenerator.accessToken(payload);
        final String bearerToken = "Bearer " + token;
        request.getHeaderWillReturn(bearerToken);

        // when, then
        assertThatThrownBy(() -> interceptorAuthProcessor.process(request))
                .isInstanceOf(ForbiddenException.class);
    }

    @ParameterizedTest
    @CsvSource({
            "GET, /api/hello",
            "POST, /api/good"
    })
    void should_PassWithoutException_when_ValidRequestWithoutTokenEntered(
            final String method,
            final String uri
    ) {
        // given
        final StubHttpServletRequest request = new StubHttpServletRequest();
        request.getMethodWillReturn(method);
        request.getRequestUriWillReturn(uri);

        // when, then
        assertThatNoException()
                .isThrownBy(() -> interceptorAuthProcessor.process(request));
    }

    @ParameterizedTest
    @CsvSource({
            "GET, /api/user",
            "POST, /api/admin"
    })
    void should_ThrowUnauthorizedException_when_InValidRequestWithoutTokenEntered(
            final String method,
            final String uri
    ) {
        // given
        final StubHttpServletRequest request = new StubHttpServletRequest();
        request.getMethodWillReturn(method);
        request.getRequestUriWillReturn(uri);

        // when, then
        assertThatThrownBy(() -> interceptorAuthProcessor.process(request))
                .isInstanceOf(UnauthorizedException.class);
    }
}