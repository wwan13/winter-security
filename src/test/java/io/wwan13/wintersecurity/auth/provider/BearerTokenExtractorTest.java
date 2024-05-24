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
import io.wwan13.wintersecurity.auth.AuthTestContainer;
import io.wwan13.wintersecurity.auth.stub.StubHttpServletRequest;
import io.wwan13.wintersecurity.jwt.Payload;
import io.wwan13.wintersecurity.jwt.provider.ProviderTestContainer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class BearerTokenExtractorTest extends UnitTest {

    @Test
    void should_ExtractTokenInHttpRequestHeader() {
        // given
        final Payload payload = new ProviderTestContainer.TestPayload(1, "role", "claim");
        final String token = ProviderTestContainer.tokenGenerator.accessToken(payload);

        final StubHttpServletRequest request = new StubHttpServletRequest();
        final String authorizationHeader = "Bearer " + token;
        request.getHeaderWillReturn(authorizationHeader);

        // when
        String result = AuthTestContainer.tokenExtractor.extract(request).get();

        // then
        assertThat(result).isEqualTo(token);
    }

    @ParameterizedTest
    @NullAndEmptySource
    void should_ReturnEmptyOptional_when_NoAuthorizationHeader(
            final String authorizationHeader
    ) {
        // given
        final StubHttpServletRequest request = new StubHttpServletRequest();
        request.getHeaderWillReturn(authorizationHeader);

        // when
        Optional<String> result = AuthTestContainer.tokenExtractor.extract(request);

        // then
        assertThat(result.isEmpty()).isTrue();
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"bearer ", "Bear", "Bearer", "Be", "Bearer"})
    void should_ReturnEmptyOptional_when_InvalidBearerPrefix(
            final String bearerPrefix
    ) {
        // given
        final Payload payload = new ProviderTestContainer.TestPayload(1, "role", "claim");
        final String token = ProviderTestContainer.tokenGenerator.accessToken(payload);

        final StubHttpServletRequest request = new StubHttpServletRequest();
        final String authorizationHeader = bearerPrefix + token;
        request.getHeaderWillReturn(authorizationHeader);

        // when
        Optional<String> result = AuthTestContainer.tokenExtractor.extract(request);

        // then
        assertThat(result.isEmpty()).isTrue();
    }

    @Test
    void should_ReturnEmptyOptional_when_NoTokenInAuthorizationHeader() {
        // given
        final StubHttpServletRequest request = new StubHttpServletRequest();
        final String authorizationHeader = "Bearer ";
        request.getHeaderWillReturn(authorizationHeader);

        // when
        Optional<String> result = AuthTestContainer.tokenExtractor.extract(request);

        // then
        assertThat(result.isEmpty()).isTrue();
    }
}