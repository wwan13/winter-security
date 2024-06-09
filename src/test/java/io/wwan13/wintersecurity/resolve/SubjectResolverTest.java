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

package io.wwan13.wintersecurity.resolve;

import io.wwan13.wintersecurity.UnitTest;
import io.wwan13.wintersecurity.resolve.stub.StubMethodParameter;
import io.wwan13.wintersecurity.resolve.stub.StubModerAndViesContainer;
import io.wwan13.wintersecurity.resolve.stub.StubNativeWebRequest;
import io.wwan13.wintersecurity.resolve.stub.StubWebDataBinderFactory;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SubjectResolverTest extends UnitTest {

    static SubjectResolver subjectResolver = new SubjectResolver(
            ResolveTestContainer.targetAnnotations
    );

    @Test
    void should_ReturnTrue_when_AnnotationDeclared() {
        // given
        final StubMethodParameter methodParameter = new StubMethodParameter();

        methodParameter.declaredAnnotationsWillBe(RequestUserId.class);

        // when
        boolean result = subjectResolver.supportsParameter(methodParameter);

        // then
        assertThat(result).isTrue();
    }

    @Test
    void should_ReturnFalse_when_AnnotationNotDeclared() {
        // given
        final StubMethodParameter methodParameter = new StubMethodParameter();

        methodParameter.declaredAnnotationsWillBe(Set.of());
        methodParameter.parameterTypeWillBe(Long.class);

        // when
        boolean result = subjectResolver.supportsParameter(methodParameter);

        // then
        assertThat(result).isFalse();
    }

    @Test
    void should_ResolveSubject() {
        // given
        final StubMethodParameter methodParameter = new StubMethodParameter();
        final StubModerAndViesContainer modelAndViewContainer = new StubModerAndViesContainer();
        final StubNativeWebRequest nativeWebRequest = new StubNativeWebRequest();
        final StubWebDataBinderFactory webDataBinderFactory = new StubWebDataBinderFactory();

        nativeWebRequest.requestAttributesWillBe(ResolveTestContainer.defaultTestClaims);
        methodParameter.parameterTypeWillBe(Long.class);

        // when
        Object value = subjectResolver.resolveArgument(
                methodParameter,
                modelAndViewContainer,
                nativeWebRequest,
                webDataBinderFactory
        );

        // then
        assertThat(value.getClass()).isAssignableFrom(Long.class);
        assertThat((Long) value).isEqualTo(1L);
    }

    @Test
    void should_ThrowException_when_InValidParameterType() {
        // given
        final StubMethodParameter methodParameter = new StubMethodParameter();
        final StubModerAndViesContainer modelAndViewContainer = new StubModerAndViesContainer();
        final StubNativeWebRequest nativeWebRequest = new StubNativeWebRequest();
        final StubWebDataBinderFactory webDataBinderFactory = new StubWebDataBinderFactory();

        nativeWebRequest.requestAttributesWillBe(ResolveTestContainer.defaultTestClaims);
        methodParameter.parameterTypeWillBe(List.class);

        // when, then
        assertThatThrownBy(() ->
                subjectResolver.resolveArgument(
                        methodParameter,
                        modelAndViewContainer,
                        nativeWebRequest,
                        webDataBinderFactory
                )
        ).isInstanceOf(IllegalStateException.class);
    }
}