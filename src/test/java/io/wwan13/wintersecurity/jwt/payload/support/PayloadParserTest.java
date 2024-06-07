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
import io.wwan13.wintersecurity.jwt.PayloadParser;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class PayloadParserTest extends UnitTest {

    @Test
    void should_SubjectConvertToString_when_SubjectIsWrapperClass() {
        // given
        final Long subject = 1L;
        final Set<String> roles = Set.of("role");
        Object payload = new TestJwtPayloads.JwtPayloadWithWrapperClassSubject(subject, roles);

        PayloadAnalysis payloadAnalysis =
                getPayloadAnalysis(TestJwtPayloads.JwtPayloadWithWrapperClassSubject.class);
        PayloadParser payloadParser = new JwtPayloadParser(payloadAnalysis);

        // when
        String result = payloadParser.asSubject(payload);

        // then
        assertThat(result).isEqualTo(subject.toString());
    }

    @Test
    void should_SubjectConvertToString_when_SubjectIsDataType() {
        // given
        final long subject = 1L;
        final Set<String> roles = Set.of("role");
        Object payload = new TestJwtPayloads.JwtPayloadWithDataTypeSubject(subject, roles);

        PayloadAnalysis payloadAnalysis =
                getPayloadAnalysis(TestJwtPayloads.JwtPayloadWithDataTypeSubject.class);
        PayloadParser payloadParser = new JwtPayloadParser(payloadAnalysis);

        // when
        String result = payloadParser.asSubject(payload);

        // then
        assertThat(result).isEqualTo(Objects.toString(subject));
    }

    @Test
    void should_FindSubject_when_SubjectFieldNameIsNotSubject() {
        // given
        final long id = 1L;
        final Set<String> roles = Set.of("role");
        Object payload = new TestJwtPayloads.JwtPayloadWithSubjectFieldNameId(id, roles);

        PayloadAnalysis payloadAnalysis =
                getPayloadAnalysis(TestJwtPayloads.JwtPayloadWithSubjectFieldNameId.class);
        PayloadParser payloadParser = new JwtPayloadParser(payloadAnalysis);

        // when
        String result = payloadParser.asSubject(payload);

        // then
        assertThat(result).isEqualTo(Objects.toString(id));
    }

    @Test
    void should_RolesConvertToSet_when_RolesIsCollectionType() {
        // given
        final long subject = 1L;
        final Set<String> roles = Set.of("role");
        Object payload = new TestJwtPayloads.JwtPayloadWithCollectionClassRoles(subject, roles);

        PayloadAnalysis payloadAnalysis =
                getPayloadAnalysis(TestJwtPayloads.JwtPayloadWithCollectionClassRoles.class);
        PayloadParser payloadParser = new JwtPayloadParser(payloadAnalysis);

        // when
        Set<String> result = payloadParser.asRoles(payload);

        // then
        assertThat(result).isEqualTo(roles);
    }

    @Test
    void should_RolesConvertToSet_when_RolesIsNoneCollectionType() {
        // given
        final long subject = 1L;
        final String roles = "role";
        Object payload = new TestJwtPayloads.JwtPayloadWithNoneCollectionClassRoles(subject, roles);

        PayloadAnalysis payloadAnalysis =
                getPayloadAnalysis(TestJwtPayloads.JwtPayloadWithNoneCollectionClassRoles.class);
        PayloadParser payloadParser = new JwtPayloadParser(payloadAnalysis);

        // when
        Set<String> result = payloadParser.asRoles(payload);

        // then
        assertThat(result).isEqualTo(Set.of(roles));
    }

    @Test
    void should_RolesConvertToStringSet_when_RolesIsOtherObjectSet() {
        // given
        final long subject = 1L;
        final Set<Object> roles = Set.of(1, 2);
        Object payload = new TestJwtPayloads.JwtPayloadWithOtherObjectSetRoles(subject, roles);

        PayloadAnalysis payloadAnalysis =
                getPayloadAnalysis(TestJwtPayloads.JwtPayloadWithOtherObjectSetRoles.class);
        PayloadParser payloadParser = new JwtPayloadParser(payloadAnalysis);

        // when
        Set<String> result = payloadParser.asRoles(payload);

        // then
        assertThat(result).contains("1", "2");
    }

    @Test
    void should_FindRoles_when_RolesFieldNameIsNotRoles() {
        // given
        final long subject = 1L;
        final Set<String> authorities = Set.of("role");
        Object payload = new TestJwtPayloads.JwtPayloadWithRolesFieldNameAuthorities(subject, authorities);

        PayloadAnalysis payloadAnalysis =
                getPayloadAnalysis(TestJwtPayloads.JwtPayloadWithRolesFieldNameAuthorities.class);
        PayloadParser payloadParser = new JwtPayloadParser(payloadAnalysis);

        // when
        Set<String> result = payloadParser.asRoles(payload);

        // then
        assertThat(result).isEqualTo(authorities);
    }

    @Test
    void should_ConvertToObjectMap_when_BothDataTypeAndWrapperClassClaims() {
        // given
        final long subject = 1L;
        final Set<String> roles = Set.of("role");
        final long dataTypeClaim = 1L;
        final Long wrapperClassClaim = 1L;
        Object payload = new TestJwtPayloads
                .JwtPayloadWithDataTypeAndWrapperClassClaims(subject, roles, dataTypeClaim, wrapperClassClaim);

        PayloadAnalysis payloadAnalysis =
                getPayloadAnalysis(TestJwtPayloads.JwtPayloadWithDataTypeAndWrapperClassClaims.class);
        PayloadParser payloadParser = new JwtPayloadParser(payloadAnalysis);

        // when
        Map<String, Object> result = payloadParser.asAdditionalClaims(payload);

        // then
        result.keySet().forEach(key ->
                assertThat(result.get(key))
                        .isEqualTo(1L)
                        .isInstanceOf(Object.class)

        );
    }

    @Test
    void should_ConvertToObjectMap_when_BothAnnotationIsExistAndNotExist() {
        // given
        final long subject = 1L;
        final Set<String> roles = Set.of("role");
        final long claim = 1L;
        Object payload = new TestJwtPayloads
                .JwtPayloadWithAnnotatedClaimAndNotAnnotatedClaim(subject, roles, claim, claim);

        PayloadAnalysis payloadAnalysis =
                getPayloadAnalysis(TestJwtPayloads.JwtPayloadWithAnnotatedClaimAndNotAnnotatedClaim.class);
        PayloadParser payloadParser = new JwtPayloadParser(payloadAnalysis);

        // when
        Map<String, Object> result = payloadParser.asAdditionalClaims(payload);

        // then
        assertThat(result.keySet().size()).isEqualTo(2);
    }

    @Test
    void should_KeyIsFieldName_when_ValueIsNotEntered() {
        // given
        final long subject = 1L;
        final Set<String> roles = Set.of("role");
        final long claim = 1L;
        Object payload = new TestJwtPayloads
                .JwtPayloadWithAnnotatedClaimAndNotAnnotatedClaim(subject, roles, claim, claim);

        PayloadAnalysis payloadAnalysis =
                getPayloadAnalysis(TestJwtPayloads.JwtPayloadWithAnnotatedClaimAndNotAnnotatedClaim.class);
        PayloadParser payloadParser = new JwtPayloadParser(payloadAnalysis);

        // when
        Map<String, Object> result = payloadParser.asAdditionalClaims(payload);

        // then
        assertThat(result.keySet()).contains("annotated", "notAnnotated");
    }

    private PayloadAnalysis getPayloadAnalysis(Class<?> payloadClazz) {
        PayloadAnalyst payloadAnalyst = new DefaultPayloadAnalyst();
        return payloadAnalyst.analyze(payloadClazz);
    }
}