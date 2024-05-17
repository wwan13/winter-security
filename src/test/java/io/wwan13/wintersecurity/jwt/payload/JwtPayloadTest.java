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

import io.wwan13.wintersecurity.UnitTest;
import io.wwan13.wintersecurity.jwt.Payload;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtPayloadTest extends UnitTest {

    @Test
    void should_SubjectConvertToString_when_SubjectIsWrapperClass() {
        // given
        final Long subject = 1L;
        final Set<String> roles = Set.of("role");
        Payload payload = new TestJwtPayloads.JwtPayloadWithWrapperClassSubject(subject, roles);

        // when
        String result = payload.asSubject();

        // then
        assertThat(result).isEqualTo(subject.toString());
    }

    @Test
    void should_SubjectConvertToString_when_SubjectIsDataType() {
        // given
        final long subject = 1L;
        final Set<String> roles = Set.of("role");
        Payload payload = new TestJwtPayloads.JwtPayloadWithDataTypeSubject(subject, roles);

        // when
        String result = payload.asSubject();

        // then
        assertThat(result).isEqualTo(Objects.toString(subject));
    }

    @Test
    void should_FindSubject_when_SubjectFieldNameIsNotSubject() {
        // given
        final long id = 1L;
        final Set<String> roles = Set.of("role");
        Payload payload = new TestJwtPayloads.JwtPayloadWithSubjectFieldNameId(id, roles);

        // when
        String result = payload.asSubject();

        // then
        assertThat(result).isEqualTo(Objects.toString(id));
    }

    @Test
    void should_ThrowsException_when_SubjectIsNotExist() {
        // given
        final Set<String> roles = Set.of("role");
        Payload payload = new TestJwtPayloads.JwtPayloadWithNoSubject(roles);

        // when, then
        assertThatThrownBy(payload::asSubject)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cannot be empty");
    }

    @Test
    void should_ThrowsException_when_SubjectIsMoreThanTwo() {
        // given
        final long subject1 = 1L;
        final long subject2 = 2L;
        final Set<String> roles = Set.of("role");
        Payload payload = new TestJwtPayloads.JwtPayloadWithTwoSubject(subject1, subject2, roles);

        // when, then
        assertThatThrownBy(payload::asSubject)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cannot be more than");
    }

    @Test
    void should_RolesConvertToSet_when_RolesIsCollectionType() {
        // given
        final long subject = 1L;
        final Set<String> roles = Set.of("role");
        Payload payload = new TestJwtPayloads.JwtPayloadWithCollectionClassRoles(subject, roles);

        // when
        Set<String> result = payload.asRoles();

        // then
        assertThat(result).isEqualTo(roles);
    }

    @Test
    void should_RolesConvertToSet_when_RolesIsNoneCollectionType() {
        // given
        final long subject = 1L;
        final String roles = "role";
        Payload payload = new TestJwtPayloads.JwtPayloadWithNoneCollectionClassRoles(subject, roles);

        // when
        Set<String> result = payload.asRoles();

        // then
        assertThat(result).isEqualTo(Set.of(roles));
    }

    @Test
    void should_RolesConvertToStringSet_when_RolesIsOtherObjectSet() {
        // given
        final long subject = 1L;
        final Set<Object> roles = Set.of(1, 2);
        Payload payload = new TestJwtPayloads.JwtPayloadWithOtherObjectSetRoles(subject, roles);

        // when
        Set<String> result = payload.asRoles();

        // then
        assertThat(result).contains("1", "2");
    }

    @Test
    void should_FindRoles_when_RolesFieldNameIsNotRoles() {
        // given
        final long subject = 1L;
        final Set<String> authorities = Set.of("role");
        Payload payload = new TestJwtPayloads.JwtPayloadWithRolesFieldNameAuthorities(subject, authorities);

        // when
        Set<String> result = payload.asRoles();

        // then
        assertThat(result).isEqualTo(authorities);
    }

    @Test
    void should_ThrowsException_when_RolesIsNotExist() {
        // given
        final long subject = 1L;
        Payload payload = new TestJwtPayloads.JwtPayloadWithNoRoles(subject);

        // when, then
        assertThatThrownBy(payload::asRoles)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cannot be empty");
    }

    @Test
    void should_ThrowsException_when_RolesIsMoreThanTwo() {
        // given
        final long subject = 1L;
        final Set<String> roles1 = Set.of("role");
        final Set<String> roles2 = Set.of("role");
        Payload payload = new TestJwtPayloads.JwtPayloadWithTwoRoles(subject, roles1, roles2);

        // when, then
        assertThatThrownBy(payload::asRoles)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cannot be more than");
    }

    @Test
    void should_ConvertToStringMap_when_BothDataTypeAndWrapperClassClaims() {
        // given
        final long subject = 1L;
        final Set<String> roles = Set.of("role");
        final long dataTypeClaim = 1L;
        final Long wrapperClassClaim = 1L;
        Payload payload = new TestJwtPayloads
                .JwtPayloadWithDataTypeAndWrapperClassClaims(subject, roles, dataTypeClaim, wrapperClassClaim);

        // when
        Map<String, String> result = payload.asAdditionalClaims();

        // then
        result.keySet().forEach(key ->
                assertThat(result.get(key)).isEqualTo("1")
        );
    }

    @Test
    void should_ConvertToStringMap_when_BothAnnotationIsExistAndNotExist() {
        // given
        final long subject = 1L;
        final Set<String> roles = Set.of("role");
        final long claim = 1L;
        Payload payload = new TestJwtPayloads
                .JwtPayloadWithAnnotatedClaimAndNotAnnotatedClaim(subject, roles, claim, claim);

        // when
        Map<String, String> result = payload.asAdditionalClaims();

        // then
        assertThat(result.keySet().size()).isEqualTo(2);
    }

    @Test
    void should_KeyIsFieldName_when_ValueIsNotEntered() {
        // given
        final long subject = 1L;
        final Set<String> roles = Set.of("role");
        final long claim = 1L;
        Payload payload = new TestJwtPayloads
                .JwtPayloadWithAnnotatedClaimAndNotAnnotatedClaim(subject, roles, claim, claim);

        // when
        Map<String, String> result = payload.asAdditionalClaims();

        // then
        assertThat(result.keySet()).contains("annotated", "notAnnotated");
    }

    @Test
    void should_KeyIsChanged_when_ValueIsEntered() {
        // given
        final long subject = 1L;
        final Set<String> roles = Set.of("role");
        final long claim = 1L;
        Payload payload = new TestJwtPayloads
                .JwtPayloadWithValueEnteredClaim(subject, roles, claim);

        // when
        Map<String, String> result = payload.asAdditionalClaims();

        // then
        assertThat(result.keySet()).contains("entered");
    }
}