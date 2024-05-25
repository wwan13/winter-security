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

package io.wwan13.wintersecurity.config;

import io.wwan13.wintersecurity.auth.RequestAccessManager;
import io.wwan13.wintersecurity.auth.TokenExtractor;
import io.wwan13.wintersecurity.auth.authorizedrequest.AuthorizedRequest;
import io.wwan13.wintersecurity.auth.processor.AbstractInterceptorAuthProcessor;
import io.wwan13.wintersecurity.auth.processor.InterceptorAuthProcessor;
import io.wwan13.wintersecurity.auth.provider.BearerTokenExtractor;
import io.wwan13.wintersecurity.auth.provider.HttpRequestAccessManager;
import io.wwan13.wintersecurity.jwt.TokenDecoder;
import org.springframework.context.annotation.Bean;

public class AuthConfiguration {

    @Bean
    public TokenExtractor tokenExtractor() {
        return new BearerTokenExtractor();
    }

    @Bean
    public RequestAccessManager requestAccessManager(AuthorizedRequest authorizedRequest) {
        return new HttpRequestAccessManager(authorizedRequest);
    }

    @Bean
    public AbstractInterceptorAuthProcessor authProcessor(
            TokenExtractor tokenExtractor,
            TokenDecoder tokenDecoder,
            RequestAccessManager requestAccessManager
    ) {
        return new InterceptorAuthProcessor(
                tokenExtractor,
                tokenDecoder,
                requestAccessManager
        );
    }
}
