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

import io.wwan13.wintersecurity.jwt.JwtProperties;
import io.wwan13.wintersecurity.jwt.support.JwtPropertiesApplier;
import io.wwan13.wintersecurity.jwt.support.JwtPropertiesRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;

public class JwtConfigurer {

    private final WebSecurityConfigurer webSecurityConfigurer;

    public JwtConfigurer(WebSecurityConfigurer webSecurityConfigurer) {
        this.webSecurityConfigurer = webSecurityConfigurer;
    }

    @Bean
    @ConditionalOnBean({WebSecurityConfigurer.class})
    public JwtProperties jwtProperties() {
        JwtPropertiesRegistry registry = new JwtPropertiesRegistry();
        webSecurityConfigurer.configureJwt(registry);
        return JwtPropertiesApplier.apply(registry);
    }
}