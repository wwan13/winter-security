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

import io.wwan13.wintersecurity.resolve.RolesResolver;
import io.wwan13.wintersecurity.resolve.SubjectResolver;
import io.wwan13.wintersecurity.resolve.TargetAnnotations;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

public class ArgumentResolversRegistrar implements WebMvcConfigurer {

    private final TargetAnnotations targetAnnotations;

    public ArgumentResolversRegistrar(TargetAnnotations targetAnnotations) {
        this.targetAnnotations = targetAnnotations;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        SubjectResolver subjectResolver = new SubjectResolver(targetAnnotations);
        resolvers.add(subjectResolver);

        RolesResolver rolesResolver = new RolesResolver(targetAnnotations);
        resolvers.add(rolesResolver);
    }
}
