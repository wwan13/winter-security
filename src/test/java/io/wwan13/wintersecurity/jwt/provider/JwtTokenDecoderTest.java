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

package io.wwan13.wintersecurity.jwt.provider;

import io.wwan13.wintersecurity.exception.unauthirized.UnauthorizedException;
import io.wwan13.wintersecurity.jwt.JwtProperties;
import io.wwan13.wintersecurity.jwt.Payload;
import io.wwan13.wintersecurity.jwt.TokenDecoder;
import io.wwan13.wintersecurity.jwt.TokenGenerator;
import io.wwan13.wintersecurity.jwt.payload.util.RoleSerializer;
import io.wwan13.wintersecurity.jwt.support.JwtPropertiesApplier;
import io.wwan13.wintersecurity.jwt.support.JwtPropertiesRegistry;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static io.wwan13.wintersecurity.jwt.provider.ProviderTestContainer.tokenDecoder;
import static io.wwan13.wintersecurity.jwt.provider.ProviderTestContainer.tokenGenerator;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTokenDecoderTest {

    @Test
    void should_DecodeToken() {
        // given
        final long id = 1L;
        final String role = "role";
        final String claim = "claim";
        Payload payload = new ProviderTestContainer.TestPayload(id, role, claim);

        String accessToken = tokenGenerator.accessToken(payload);

        // when
        Map<String, Object> decodedClaims = tokenDecoder.decode(accessToken);

        // then
        assertThat(decodedClaims.get("sub")).isEqualTo(Objects.toString(id));
        assertThat(decodedClaims.get("roles")).isEqualTo(RoleSerializer.serialize(Set.of(role)));
        assertThat(decodedClaims.get("claim")).isEqualTo(claim);
    }

    @Test
    void should_ThrowException_when_InvalidTokenEntered() {
        // given
        final String invalidToken = "invalid-token";

        // when, then
        assertThatThrownBy(() -> tokenDecoder.decode(invalidToken))
                .isInstanceOf(UnauthorizedException.class)
                .hasFieldOrPropertyWithValue("httpStatusCode", 401)
                .hasFieldOrPropertyWithValue("errorCode", "INVALID_JWT_TOKEN");
    }

    @Test
    void should_ThrowException_when_ExpiredTokenEntered() {
        // given
        final JwtProperties properties = JwtPropertiesApplier.apply(
                new JwtPropertiesRegistry()
                        .secretKey("secretsecretsecretsecretsecretsecretsecretsecretsecretsecret")
                        .accessTokenValidity(-1L)
                        .payloadClazz(ProviderTestContainer.TestPayload.class)
        );
        final TokenGenerator tokenGenerator = new JwtTokenGenerator(properties, ProviderTestContainer.payloadParser);
        final TokenDecoder tokenDecoder = new JwtTokenDecoder(properties);

        final long id = 1L;
        final String role = "role";
        final String claim = "claim";
        Payload payload = new ProviderTestContainer.TestPayload(id, role, claim);

        final String invalidToken = tokenGenerator.accessToken(payload);


        // when, then
        assertThatThrownBy(() -> tokenDecoder.decode(invalidToken))
                .isInstanceOf(UnauthorizedException.class)
                .hasFieldOrPropertyWithValue("httpStatusCode", 401)
                .hasFieldOrPropertyWithValue("errorCode", "EXPIRED_JWT_TOKEN");
    }
}