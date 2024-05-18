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

package io.wwan13.wintersecurity.jwt;

import io.jsonwebtoken.security.Keys;
import io.wwan13.wintersecurity.UnitTest;
import io.wwan13.wintersecurity.jwt.payload.DefaultPayload;
import org.junit.jupiter.api.Test;

import java.security.Key;

import static org.assertj.core.api.Assertions.assertThat;

class JwtPropertiesTest extends UnitTest {

    @Test
    void should_CreateJwtPropertiesClass_when_DateEntered() {
        // given
        final String secretKey = "secretkey123123123123123123123123123123123123123123123123";
        final long accessTokenValidity = 1000L;
        final long refreshTokenValidity = 1000L;
        final Class<? extends Payload> payloadClass = DefaultPayload.class;
        final Class<?> subjectClass = long.class;
        final Key key = Keys.hmacShaKeyFor(secretKey.getBytes());

        // when
        JwtProperties jwtProperties = new JwtProperties(
                secretKey,
                accessTokenValidity,
                refreshTokenValidity,
                payloadClass,
                subjectClass,
                key
        );

        // then
        assertThat(jwtProperties.secretKey()).isEqualTo(secretKey);
        assertThat(jwtProperties.accessTokenValidity()).isEqualTo(accessTokenValidity);
        assertThat(jwtProperties.refreshTokenValidity()).isEqualTo(refreshTokenValidity);
        assertThat(jwtProperties.payloadClazz()).isEqualTo(payloadClass);
        assertThat(jwtProperties.subjectClazz()).isEqualTo(subjectClass);
        assertThat(jwtProperties.key()).isEqualTo(key);
    }
}