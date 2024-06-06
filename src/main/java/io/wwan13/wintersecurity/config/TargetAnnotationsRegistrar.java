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

import io.wwan13.wintersecurity.resolve.TargetAnnotations;
import io.wwan13.wintersecurity.resolve.support.TargetAnnotationsApplier;
import io.wwan13.wintersecurity.resolve.support.TargetAnnotationsRegistry;
import org.springframework.context.annotation.Bean;

public class TargetAnnotationsRegistrar {

    private final SecureRequestConfigurer secureRequestConfigurer;

    public TargetAnnotationsRegistrar(SecureRequestConfigurer secureRequestConfigurer) {
        this.secureRequestConfigurer = secureRequestConfigurer;
    }

    @Bean
    public TargetAnnotations targetAnnotations() {
        TargetAnnotationsRegistry registry = new TargetAnnotationsRegistry();
        secureRequestConfigurer.registerTargetAnnotations(registry);
        return TargetAnnotationsApplier.apply(registry);
    }
}
