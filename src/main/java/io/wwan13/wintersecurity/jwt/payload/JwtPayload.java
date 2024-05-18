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

package io.wwan13.wintersecurity.jwt.payload;

import io.wwan13.wintersecurity.jwt.Payload;
import io.wwan13.wintersecurity.jwt.payload.annotation.Claim;
import io.wwan13.wintersecurity.jwt.payload.annotation.Roles;
import io.wwan13.wintersecurity.jwt.payload.annotation.Subject;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.util.*;
import java.util.stream.Collectors;

public abstract class JwtPayload implements Payload {

    private static final int FIRST_ELEMENT_INDEX = 0;

    @Override
    public String asSubject() {
        Field field = findFieldByDeclaredAnnotation(Subject.class);
        return Objects.toString(getFieldValue(field));
    }

    @Override
    public Set<String> asRoles() {
        Field field = findFieldByDeclaredAnnotation(Roles.class);
        Object values = getFieldValue(field);

        if (values instanceof Collection<?>) {
            return ((Collection<?>) values).stream()
                    .map(Objects::toString)
                    .collect(Collectors.toUnmodifiableSet());
        }

        return Collections.singleton(Objects.toString(values));
    }

    private Field findFieldByDeclaredAnnotation(Class<? extends Annotation> declared) {
        List<Field> fields = Arrays.stream(this.getClass().getDeclaredFields())
                .filter(field -> field.isAnnotationPresent(declared))
                .toList();

        validateExistsOnlyOne(fields, declared);

        return fields.get(FIRST_ELEMENT_INDEX);
    }

    private void validateExistsOnlyOne(List<Field> fields, Class<? extends Annotation> declared) {
        if (fields.size() > 1) {
            throw new IllegalStateException(declared.getSimpleName() + " cannot be more than two");
        }
        if (fields.isEmpty()) {
            throw new IllegalStateException(declared.getSimpleName() + " cannot be empty");
        }
    }

    @Override
    public Map<String, Object> asAdditionalClaims() {
        Map<String, Object> additionalClaims = new HashMap<>();

        findAdditionalClaims().forEach(field -> {
            String key = getClaimKey(field);
            Object value = getFieldValue(field);
            additionalClaims.put(key, value);
        });

        return additionalClaims;
    }

    private List<Field> findAdditionalClaims() {
        return Arrays.stream(this.getClass().getDeclaredFields())
                .filter(this::isAdditionalClaim)
                .toList();
    }

    private boolean isAdditionalClaim(Field field) {
        return field.isAnnotationPresent(Claim.class) || field.getDeclaredAnnotations().length == 0;
    }

    private String getClaimKey(Field field) {
        try {
            String value = field.getAnnotation(Claim.class).value();
            if (value.isEmpty()) {
                return field.getName();
            }
            return value;
        } catch (NullPointerException e) {
            return field.getName();
        }
    }

    private Object getFieldValue(Field field) {
        try {
            field.setAccessible(true);
            return field.get(this);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("can't access to " + field.getClass().getSimpleName());
        }
    }
}
