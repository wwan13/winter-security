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

package io.wwan13.wintersecurity.resolve.stub;

import org.springframework.core.MethodParameter;

import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Set;

public class StubMethodParameter extends MethodParameter {

    private Class<?> parameterType;
    private Set<Class<? extends Annotation>> declaredAnnotations;

    public StubMethodParameter() {
        super(
                Arrays.stream(StubMethodParameter.class.getMethods())
                        .filter(method -> method.getName().equals("hasParameterAnnotation"))
                        .findFirst()
                        .orElseThrow(IllegalStateException::new),
                0);
    }

    public StubMethodParameter(Method method, int parameterIndex) {
        super(method, parameterIndex);
    }

    public StubMethodParameter(Method method, int parameterIndex, int nestingLevel) {
        super(method, parameterIndex, nestingLevel);
    }

    public StubMethodParameter(Constructor<?> constructor, int parameterIndex) {
        super(constructor, parameterIndex);
    }

    public StubMethodParameter(Constructor<?> constructor, int parameterIndex, int nestingLevel) {
        super(constructor, parameterIndex, nestingLevel);
    }

    public StubMethodParameter(MethodParameter original) {
        super(original);
    }

    public void parameterTypeWillBe(Class<?> parameterType) {
        this.parameterType = parameterType;
    }

    public void declaredAnnotationsWillBe(Set<Class<? extends Annotation>> annotations) {
        this.declaredAnnotations = annotations;
    }

    public void declaredAnnotationsWillBe(Class<? extends Annotation> annotation) {
        this.declaredAnnotations = Set.of(annotation);
    }

    @Override
    public Class<?> getParameterType() {
        return this.parameterType;
    }

    @Override
    public <A extends Annotation> boolean hasParameterAnnotation(Class<A> annotationType) {
        return declaredAnnotations.contains(annotationType);
    }
}
