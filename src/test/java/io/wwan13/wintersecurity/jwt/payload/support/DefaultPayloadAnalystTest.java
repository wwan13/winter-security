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

import io.wwan13.wintersecurity.UnitTest;
import io.wwan13.wintersecurity.jwt.PayloadAnalysis;
import io.wwan13.wintersecurity.jwt.PayloadAnalyst;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DefaultPayloadAnalystTest extends UnitTest {

    static PayloadAnalyst payloadAnalyst = new DefaultPayloadAnalyst();

    @Test
    void should_AnalyzePayloadFields() {
        // given
        final Class<?> payloadClazz =
                TestJwtPayloads.JwtPayloadWithWrapperClassSubject.class;

        // when
        PayloadAnalysis payloadAnalysis = payloadAnalyst.analyze(payloadClazz);

        // then
        assertThat(payloadAnalysis.payloadClazz()).isInstanceOf(Class.class);
        assertThat(payloadAnalysis.subject().getName()).isEqualTo("subject");
        assertThat(payloadAnalysis.roles().getName()).isEqualTo("roles");
    }

    @Test
    void should_ThrowException_when_NoSubjectDeclared() {
        // given
        final Class<?> payloadClazz = TestJwtPayloads.JwtPayloadWithNoSubject.class;

        // when, then
        assertThatThrownBy(() -> payloadAnalyst.analyze(payloadClazz))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void should_ThrowException_when_MoreThanTwoSubjectDeclared() {
        // given
        final Class<?> payloadClazz = TestJwtPayloads.JwtPayloadWithTwoSubject.class;

        // when, then
        assertThatThrownBy(() -> payloadAnalyst.analyze(payloadClazz))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void should_ThrowException_when_NoRolesDeclared() {
        // given
        final Class<?> payloadClazz = TestJwtPayloads.JwtPayloadWithNoRoles.class;

        // when, then
        assertThatThrownBy(() -> payloadAnalyst.analyze(payloadClazz))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void should_ThrowException_when_MoreThanTwoRolesDeclared() {
        // given
        final Class<?> payloadClazz = TestJwtPayloads.JwtPayloadWithTwoRoles.class;

        // when, then
        assertThatThrownBy(() -> payloadAnalyst.analyze(payloadClazz))
                .isInstanceOf(IllegalStateException.class);
    }
}