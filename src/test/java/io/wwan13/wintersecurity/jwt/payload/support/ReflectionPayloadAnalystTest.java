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
import io.wwan13.wintersecurity.jwt.JwtProperties;
import io.wwan13.wintersecurity.jwt.Payload;
import io.wwan13.wintersecurity.jwt.PayloadAnalysis;
import io.wwan13.wintersecurity.jwt.PayloadAnalyst;
import io.wwan13.wintersecurity.jwt.support.JwtPropertiesApplier;
import io.wwan13.wintersecurity.jwt.support.JwtPropertiesRegistry;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReflectionPayloadAnalystTest extends UnitTest {

    static PayloadAnalyst payloadAnalyst = new ReflectionPayloadAnalyst();

    @Test
    void should_AnalyzePayloadFields() {
        // given
        JwtProperties jwtProperties =
                getJwtProperties(TestJwtPayloads.JwtPayloadWithDataTypeAndWrapperClassClaims.class);

        // when
        PayloadAnalysis payloadAnalysis = payloadAnalyst.analyze(jwtProperties);

        // then
        assertThat(payloadAnalysis.subject().getName()).isEqualTo("subject");
        assertThat(payloadAnalysis.roles().getName()).isEqualTo("roles");
        assertThat(payloadAnalysis.additionalClaims().stream().map(Field::getName))
                .contains("wrapperClassClaim", "dataTypeClaim");
    }

    @Test
    void should_ThrowException_when_NoSubjectDeclared() {
        // given
        JwtProperties jwtProperties =
                getJwtProperties(TestJwtPayloads.JwtPayloadWithNoSubject.class);

        // when, then
        assertThatThrownBy(() -> payloadAnalyst.analyze(jwtProperties))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void should_ThrowException_when_MoreThanTwoSubjectDeclared() {
        // given
        JwtProperties jwtProperties =
                getJwtProperties(TestJwtPayloads.JwtPayloadWithTwoSubject.class);

        // when, then
        assertThatThrownBy(() -> payloadAnalyst.analyze(jwtProperties))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void should_ThrowException_when_NoRolesDeclared() {
        // given
        JwtProperties jwtProperties =
                getJwtProperties(TestJwtPayloads.JwtPayloadWithNoRoles.class);

        // when, then
        assertThatThrownBy(() -> payloadAnalyst.analyze(jwtProperties))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void should_ThrowException_when_MoreThanTwoRolesDeclared() {
        // given
        JwtProperties jwtProperties =
                getJwtProperties(TestJwtPayloads.JwtPayloadWithTwoRoles.class);

        // when, then
        assertThatThrownBy(() -> payloadAnalyst.analyze(jwtProperties))
                .isInstanceOf(IllegalStateException.class);
    }

    private JwtProperties getJwtProperties(Class<? extends Payload> payloadClazz) {
        return JwtPropertiesApplier.apply(
                new JwtPropertiesRegistry()
                        .secretKey("asdasdasdasdasdasdasdasdasdasdasdasdasd")
                        .payloadClazz(payloadClazz)
                        .subjectClazz(long.class)
        );
    }
}