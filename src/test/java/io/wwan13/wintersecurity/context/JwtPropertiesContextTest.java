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

package io.wwan13.wintersecurity.context;

import io.wwan13.wintersecurity.ContextTest;
import io.wwan13.wintersecurity.context.config.TestContextConfig;
import io.wwan13.wintersecurity.jwt.JwtProperties;
import io.wwan13.wintersecurity.jwt.payload.DefaultPayload;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;

@Import({TestContextConfig.class})
public class JwtPropertiesContextTest extends ContextTest {

    @Autowired
    JwtProperties jwtProperties;

    @Test
    void should_RegisteredInSpringIocWithEnteredValue_when_ContextLoaded() {
        // given, then, then
        assertThat(jwtProperties.secretKey())
                .isEqualTo("secretkey123123123123123123123123123123123123123123123123");
        assertThat(jwtProperties.accessTokenValidity()).isEqualTo(1000L);
        assertThat(jwtProperties.refreshTokenValidity()).isEqualTo(1000L);
        assertThat(jwtProperties.payloadClazz()).isEqualTo(DefaultPayload.class);
        assertThat(jwtProperties.subjectClazz()).isEqualTo(long.class);
    }
}
