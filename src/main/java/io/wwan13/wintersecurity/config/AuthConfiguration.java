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
import io.wwan13.wintersecurity.auth.authpattern.AuthPatterns;
import io.wwan13.wintersecurity.auth.processor.AbstractInterceptorAuthProcessor;
import io.wwan13.wintersecurity.auth.processor.InterceptorAuthProcessor;
import io.wwan13.wintersecurity.auth.provider.BearerTokenExtractor;
import io.wwan13.wintersecurity.auth.provider.HttpRequestAccessManager;
import io.wwan13.wintersecurity.jwt.TokenDecoder;
import io.wwan13.wintersecurity.jwt.provider.JwtTokenDecoder;
import io.wwan13.wintersecurity.passwordencoder.PasswordEncoder;
import io.wwan13.wintersecurity.secretkey.SecretKey;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class AuthConfiguration {

    @Bean
    @ConditionalOnMissingBean(TokenDecoder.class)
    public TokenDecoder tokenDecoder(SecretKey secretKey) {
        return new JwtTokenDecoder(secretKey);
    }

    @Bean
    public TokenExtractor tokenExtractor() {
        return new BearerTokenExtractor();
    }

    @Bean
    public RequestAccessManager requestAccessManager(AuthPatterns authPatterns) {
        return new HttpRequestAccessManager(authPatterns);
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

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new PasswordEncoder(new BCryptPasswordEncoder());
    }
}
