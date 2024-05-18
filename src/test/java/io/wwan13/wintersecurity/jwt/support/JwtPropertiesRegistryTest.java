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

package io.wwan13.wintersecurity.jwt.support;

import io.jsonwebtoken.security.Keys;
import io.wwan13.wintersecurity.constant.Constants;
import io.wwan13.wintersecurity.jwt.JwtProperties;
import io.wwan13.wintersecurity.jwt.Payload;
import io.wwan13.wintersecurity.jwt.payload.DefaultPayload;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtPropertiesRegistryTest {

    @Test
    void should_CreateJwtPropertiesClass_when_UsingJwtPropertiesRegistry() {
        // given
        final String secretKey = "secretkey123123123123123123123123123123123123123123123123";
        final long accessTokenValidity = 1000L;
        final long refreshTokenValidity = 1000L;
        final Class<? extends Payload> payloadClass = DefaultPayload.class;
        final Class<?> subjectClass = long.class;

        // when
        JwtProperties jwtProperties = new JwtPropertiesRegistry()
                .secretKey(secretKey)
                .accessTokenValidity(accessTokenValidity)
                .refreshTokenValidity(refreshTokenValidity)
                .payloadClazz(payloadClass)
                .subjectClazz(subjectClass)
                .apply();

        // then
        assertThat(jwtProperties).isInstanceOf(JwtProperties.class);
        assertThat(jwtProperties.secretKey()).isEqualTo(secretKey);
        assertThat(jwtProperties.accessTokenValidity()).isEqualTo(accessTokenValidity);
        assertThat(jwtProperties.refreshTokenValidity()).isEqualTo(refreshTokenValidity);
        assertThat(jwtProperties.payloadClazz()).isEqualTo(payloadClass);
        assertThat(jwtProperties.subjectClazz()).isEqualTo(subjectClass);
    }

    @Test
    void should_CreateKeyFromSecretKey_when_JwtPropertiesApplied() {
        // given
        final String secretKey = "secretkey123123123123123123123123123123123123123123123123";

        // when
        JwtProperties jwtProperties = new JwtPropertiesRegistry()
                .secretKey(secretKey)
                .apply();

        // then
        assertThat(jwtProperties.key()).isEqualTo(Keys.hmacShaKeyFor(secretKey.getBytes()));
    }

    @ParameterizedTest(name = "{index} : {0}")
    @NullAndEmptySource
    @ValueSource(strings = {
            "short secret key",
            "1234567890123456789012345678901"
    })
    void should_ThrowsException_when_SecretKeyIsEmptyOrLessThen32(final String secretKey) {
        // given
        JwtPropertiesRegistry jwtPropertiesRegistry = new JwtPropertiesRegistry()
                .secretKey(secretKey);

        // when, then
        assertThatThrownBy(jwtPropertiesRegistry::apply)
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void should_ReplaceToDefaultValue_when_ValidityAndClazzValuesNotEntered() {
        // given
        final String secretKey = "secretkey123123123123123123123123123123123123123123123123";

        // when
        JwtProperties jwtProperties = new JwtPropertiesRegistry()
                .secretKey(secretKey)
                .apply();

        // then
        assertThat(jwtProperties.accessTokenValidity()).isEqualTo(Constants.DEFAULT_ACCESS_TOKEN_VALIDITY);
        assertThat(jwtProperties.refreshTokenValidity()).isEqualTo(Constants.DEFAULT_REFRESH_TOKEN_VALIDITY);
        assertThat(jwtProperties.payloadClazz()).isEqualTo(Constants.DEFAULT_PAYLOAD_CLAZZ);
        assertThat(jwtProperties.subjectClazz()).isEqualTo(Constants.DEFAULT_SUBJECT_CLAZZ);
    }
}