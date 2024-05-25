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
import io.wwan13.wintersecurity.auth.AuthProcessor;
import io.wwan13.wintersecurity.auth.RequestAccessManager;
import io.wwan13.wintersecurity.auth.TokenExtractor;
import io.wwan13.wintersecurity.auth.processor.AbstractInterceptorAuthProcessor;
import io.wwan13.wintersecurity.auth.processor.InterceptorAuthProcessor;
import io.wwan13.wintersecurity.auth.provider.BearerTokenExtractor;
import io.wwan13.wintersecurity.auth.provider.HttpRequestAccessManager;
import io.wwan13.wintersecurity.context.config.TestContextConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.web.servlet.HandlerInterceptor;

import static org.assertj.core.api.Assertions.assertThat;

@Import({TestContextConfig.class})
public class AuthConfigurationContextTest extends ContextTest {

    @Autowired
    TokenExtractor tokenExtractor;

    @Autowired
    RequestAccessManager requestAccessManager;

    @Autowired
    AbstractInterceptorAuthProcessor authProcessor;

    @Test
    void should_RegisteredInSpringIocWithEnteredValue_when_ContextLoaded() {
        // given, then, then
        assertThat(tokenExtractor)
                .isInstanceOf(TokenExtractor.class)
                .isExactlyInstanceOf(BearerTokenExtractor.class);

        assertThat(requestAccessManager)
                .isInstanceOf(RequestAccessManager.class)
                .isExactlyInstanceOf(HttpRequestAccessManager.class);

        assertThat(authProcessor)
                .isInstanceOf(AuthProcessor.class)
                .isInstanceOf(HandlerInterceptor.class)
                .isExactlyInstanceOf(InterceptorAuthProcessor.class);
    }
}
