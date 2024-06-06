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

package io.wwan13.wintersecurity.context.jwtprovider;

import io.wwan13.wintersecurity.config.EnableJwtProvider;
import io.wwan13.wintersecurity.config.JwtProviderConfigurer;
import io.wwan13.wintersecurity.jwt.support.JwtPropertiesRegistry;
import io.wwan13.wintersecurity.secretkey.support.SecretKeyRegistry;
import org.springframework.boot.test.context.TestConfiguration;

@TestConfiguration
@EnableJwtProvider
public class JwtProviderTestConfig implements JwtProviderConfigurer {

    @Override
    public void configureJwt(JwtPropertiesRegistry registry) {
        registry
                .accessTokenValidity(100000000000L)
                .refreshTokenValidity(100000000000L);
    }

    @Override
    public void configureSecretKey(SecretKeyRegistry registry) {
        registry
                .secretKey("asdfghjklqwertyuiopzxcvbnmasddfgwerasf");
    }
}
