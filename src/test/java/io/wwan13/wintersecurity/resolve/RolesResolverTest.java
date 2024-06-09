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

import io.wwan13.wintersecurity.jwt.TokenClaims;
import io.wwan13.wintersecurity.resolve.stub.StubMethodParameter;
import io.wwan13.wintersecurity.resolve.stub.StubModerAndViesContainer;
import io.wwan13.wintersecurity.resolve.stub.StubNativeWebRequest;
import io.wwan13.wintersecurity.resolve.stub.StubWebDataBinderFactory;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RolesResolverTest {

    static RolesResolver rolesResolver = new RolesResolver(
            ResolveTestContainer.targetAnnotations
    );

    @Test
    void should_ReturnTrue_when_AnnotationDeclared() {
        // given
        final StubMethodParameter methodParameter = new StubMethodParameter();

        methodParameter.declaredAnnotationsWillBe(RequestUserRoles.class);

        // when
        boolean result = rolesResolver.supportsParameter(methodParameter);

        // then
        assertThat(result).isTrue();
    }

    @Test
    void should_ReturnFalse_when_AnnotationNotDeclared() {
        // given
        final StubMethodParameter methodParameter = new StubMethodParameter();

        methodParameter.declaredAnnotationsWillBe(Set.of());

        // when
        boolean result = rolesResolver.supportsParameter(methodParameter);

        // then
        assertThat(result).isFalse();
    }

    @Test
    void should_ResolveRoles() {
        // given
        final StubMethodParameter methodParameter = new StubMethodParameter();
        final StubModerAndViesContainer modelAndViewContainer = new StubModerAndViesContainer();
        final StubNativeWebRequest nativeWebRequest = new StubNativeWebRequest();
        final StubWebDataBinderFactory webDataBinderFactory = new StubWebDataBinderFactory();

        nativeWebRequest.requestAttributesWillBe(ResolveTestContainer.defaultTestClaims);
        methodParameter.parameterTypeWillBe(Set.class);

        // when
        Object value = rolesResolver.resolveArgument(
                methodParameter,
                modelAndViewContainer,
                nativeWebRequest,
                webDataBinderFactory
        );

        // then
        assertThat(value.getClass()).isAssignableFrom(HashSet.class);
        assertThat((Set) value).contains("ROLE_USER");
    }

    @Test
    void should_ResolveStringRole_when_NoneCollectionTypeRoleEntered() {
        // given
        final StubMethodParameter methodParameter = new StubMethodParameter();
        final StubModerAndViesContainer modelAndViewContainer = new StubModerAndViesContainer();
        final StubNativeWebRequest nativeWebRequest = new StubNativeWebRequest();
        final StubWebDataBinderFactory webDataBinderFactory = new StubWebDataBinderFactory();

        nativeWebRequest.requestAttributesWillBe(new TokenClaims(Map.of("roles", "ROLE_USER")));
        methodParameter.parameterTypeWillBe(String.class);

        final RolesResolver rolesResolver = new RolesResolver(
                ResolveTestContainer.targetAnnotations
        );

        // when
        Object value = rolesResolver.resolveArgument(
                methodParameter,
                modelAndViewContainer,
                nativeWebRequest,
                webDataBinderFactory
        );

        // then
        assertThat(value.getClass()).isAssignableFrom(String.class);
        assertThat((String) value).isEqualTo("ROLE_USER");
    }


    @Test
    void should_ThrowException_when_InValidParameterTypeDeclared() {
        // given
        final StubMethodParameter methodParameter = new StubMethodParameter();
        final StubModerAndViesContainer modelAndViewContainer = new StubModerAndViesContainer();
        final StubNativeWebRequest nativeWebRequest = new StubNativeWebRequest();
        final StubWebDataBinderFactory webDataBinderFactory = new StubWebDataBinderFactory();

        nativeWebRequest.requestAttributesWillBe(ResolveTestContainer.defaultTestClaims);
        methodParameter.parameterTypeWillBe(Long.class);

        // when
        assertThatThrownBy(() ->
                rolesResolver.resolveArgument(
                        methodParameter,
                        modelAndViewContainer,
                        nativeWebRequest,
                        webDataBinderFactory
                )
        ).isInstanceOf(IllegalStateException.class);
    }
}