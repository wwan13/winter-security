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
import io.wwan13.wintersecurity.jwt.PayloadAnalysis;
import io.wwan13.wintersecurity.jwt.PayloadParser;
import io.wwan13.wintersecurity.jwt.TokenDecoder;
import io.wwan13.wintersecurity.jwt.TokenGenerator;
import io.wwan13.wintersecurity.jwt.payload.support.JwtPayloadParser;
import io.wwan13.wintersecurity.jwt.provider.JwtTokenDecoder;
import io.wwan13.wintersecurity.jwt.provider.JwtTokenGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;

@Deprecated
@Import({TestContextConfig.class})
public class JwtConfigurationContextTest extends ContextTest {

    @Autowired
    TokenGenerator tokenGenerator;

    @Autowired
    TokenDecoder tokenDecoder;

    @Autowired
    PayloadAnalysis payloadAnalysis;

    @Autowired
    PayloadParser payloadParser;

    @Test
    void should_RegisteredInSpringIocWithEnteredValue_when_ContextLoaded() {
        // given, then, then
        assertThat(tokenGenerator)
                .isInstanceOf(TokenGenerator.class)
                .isExactlyInstanceOf(JwtTokenGenerator.class);

        assertThat(tokenDecoder)
                .isInstanceOf(TokenDecoder.class)
                .isExactlyInstanceOf(JwtTokenDecoder.class);

        assertThat(payloadAnalysis)
                .isInstanceOf(PayloadAnalysis.class);

        assertThat(payloadParser)
                .isInstanceOf(PayloadParser.class)
                .isExactlyInstanceOf(JwtPayloadParser.class);
    }
}
