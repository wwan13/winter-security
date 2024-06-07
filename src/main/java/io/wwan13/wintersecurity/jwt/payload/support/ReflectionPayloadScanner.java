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

package io.wwan13.wintersecurity.jwt.payload.support;

import io.wwan13.wintersecurity.jwt.PayloadScanner;
import io.wwan13.wintersecurity.jwt.payload.DefaultPayload;
import io.wwan13.wintersecurity.jwt.payload.annotation.Payload;
import org.reflections.Reflections;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.scanners.TypeAnnotationsScanner;

import java.util.Set;

public class ReflectionPayloadScanner implements PayloadScanner {

    private static final String DEFAULT_SCAN_BASE_PACKAGE = "";

    @Override
    public Class<?> scan() {
        Reflections reflections = new Reflections(
                DEFAULT_SCAN_BASE_PACKAGE,
                new TypeAnnotationsScanner(),
                new SubTypesScanner()
        );

        Set<Class<?>> payloads = reflections.getTypesAnnotatedWith(Payload.class);
        validateMoreThanTwo(payloads);

        return payloads.stream()
                .findFirst()
                .orElse(DefaultPayload.class);
    }

    public void validateMoreThanTwo(Set<Class<?>> payloads) {
        if (payloads.size() > 1) {
            throw new IllegalStateException("Must be only one payload.");
        }
    }
}
