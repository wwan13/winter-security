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
import io.wwan13.wintersecurity.jwt.PayloadAnalyst;
import io.wwan13.wintersecurity.jwt.payload.annotation.Claim;
import io.wwan13.wintersecurity.jwt.payload.annotation.Roles;
import io.wwan13.wintersecurity.jwt.payload.annotation.Subject;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class DefaultPayloadAnalyst implements PayloadAnalyst {

    private static final int FIRST_ELEMENT_INDEX = 0;

    @Override
    public PayloadAnalysis analyze(Class<?> payloadClazz) {
        Field subject = findFieldByDeclaredAnnotation(payloadClazz, Subject.class);
        Field roles = findFieldByDeclaredAnnotation(payloadClazz, Roles.class);
        Set<Field> additionalClaims = findAdditionalClaimFields(payloadClazz);

        return new PayloadAnalysis(payloadClazz, subject, roles, additionalClaims);
    }

    private Field findFieldByDeclaredAnnotation(
            Class<?> payloadClazz,
            Class<? extends Annotation> declared
    ) {
        List<Field> fields = Arrays.stream(payloadClazz.getDeclaredFields())
                .filter(field -> field.isAnnotationPresent(declared))
                .toList();

        validateExistsOnlyOne(fields, declared);

        return fields.get(FIRST_ELEMENT_INDEX);
    }

    private void validateExistsOnlyOne(
            List<Field> fields,
            Class<? extends Annotation> declared
    ) {
        if (fields.size() > 1) {
            throw new IllegalStateException(declared.getSimpleName() + " cannot be more than two");
        }
        if (fields.isEmpty()) {
            throw new IllegalStateException(declared.getSimpleName() + " cannot be empty");
        }
    }

    private Set<Field> findAdditionalClaimFields(
            Class<?> payloadClazz
    ) {
        return Arrays.stream(payloadClazz.getDeclaredFields())
                .filter(this::isAdditionalClaim)
                .collect(Collectors.toUnmodifiableSet());
    }

    private boolean isAdditionalClaim(Field field) {
        return field.isAnnotationPresent(Claim.class) || field.getDeclaredAnnotations().length == 0;
    }
}
