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

package io.wwan13.wintersecurity.context.config;

import io.wwan13.wintersecurity.auth.authorizedrequest.support.AuthorizedRequestRegistry;
import io.wwan13.wintersecurity.config.EnableWebSecurity;
import io.wwan13.wintersecurity.config.WebSecurityConfigurer;
import io.wwan13.wintersecurity.jwt.payload.DefaultPayload;
import io.wwan13.wintersecurity.jwt.support.JwtPropertiesRegistry;
import io.wwan13.wintersecurity.resolve.RequestUserId;
import io.wwan13.wintersecurity.resolve.RequestUserRoles;
import io.wwan13.wintersecurity.resolve.support.TargetAnnotationsRegistry;
import org.springframework.boot.test.context.TestConfiguration;

@TestConfiguration
@EnableWebSecurity
public class TestContextConfig implements WebSecurityConfigurer {

    @Override
    public void registerAuthPatterns(AuthorizedRequestRegistry registry) {
        registry
                .uriPatterns("/api/test/**")
                .allHttpMethods()
                .permitAll()

                .elseRequestAuthenticated();
    }

    @Override
    public void configureJwt(JwtPropertiesRegistry registry) {
        registry
                .secretKey("secretkey123123123123123123123123123123123123123123123123")
                .accessTokenValidity(1000L)
                .refreshTokenValidity(1000L)
                .payloadClazz(DefaultPayload.class)
                .subjectClazz(long.class);
    }

    @Override
    public void registerResolveTargets(TargetAnnotationsRegistry registry) {
        registry
                .addSubjectResolveAnnotation(RequestUserId.class)
                .addRolesResolveAnnotation(RequestUserRoles.class);
    }
}
