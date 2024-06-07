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

import io.wwan13.wintersecurity.jwt.PayloadAnalysis;
import io.wwan13.wintersecurity.jwt.PayloadParser;

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtPayloadParser implements PayloadParser {

    private final PayloadAnalysis payloadAnalysis;

    public JwtPayloadParser(PayloadAnalysis payloadAnalysis) {
        this.payloadAnalysis = payloadAnalysis;
    }

    @Override
    public String asSubject(Object payload) {
        Field field = payloadAnalysis.subject();
        return Objects.toString(getFieldValue(payload, field));
    }

    @Override
    public Set<String> asRoles(Object payload) {
        Field field = payloadAnalysis.roles();
        Object values = getFieldValue(payload, field);

        if (values instanceof Collection<?>) {
            return ((Collection<?>) values).stream()
                    .map(Objects::toString)
                    .collect(Collectors.toUnmodifiableSet());
        }

        return Collections.singleton(Objects.toString(values));
    }

    @Override
    public Map<String, Object> asAdditionalClaims(Object payload) {
        Set<Field> fields = payloadAnalysis.additionalClaims();
        Map<String, Object> additionalClaims = new HashMap<>();

        fields.forEach(field ->
                additionalClaims.put(field.getName(), getFieldValue(payload, field)));

        return additionalClaims;
    }

    private Object getFieldValue(Object payload, Field field) {
        try {
            field.setAccessible(true);
            return field.get(payload);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("can't access to " + field.getClass().getSimpleName());
        }
    }
}
