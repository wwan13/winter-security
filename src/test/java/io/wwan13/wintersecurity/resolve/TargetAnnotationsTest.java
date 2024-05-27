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
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class TargetAnnotationsTest extends UnitTest {

    @Test
    void should_ContainsTargetAnnotationInfo() {
        // given
        final Class<? extends Annotation> forSubject = RequestUserSubject.class;
        final Class<? extends Annotation> forRoles = RequestUserRoles.class;
        final Class<? extends Annotation> forClaims = RequestUserClaims.class;
        final Class<? extends Annotation> forClaim = RequestUserClaim.class;
        final Class<? extends Annotation> forPayload = RequestUserPayload.class;

        // when
        TargetAnnotations targetAnnotations = new TargetAnnotations(
                Set.of(forSubject),
                Set.of(forRoles),
                Set.of(forClaims),
                Set.of(forClaim),
                Set.of(forPayload)
        );

        // then
        assertThat(targetAnnotations).isInstanceOf(TargetAnnotations.class);
        assertThat(targetAnnotations.forSubject()).contains(forSubject);
        assertThat(targetAnnotations.forRoles()).contains(forRoles);
        assertThat(targetAnnotations.forClaims()).contains(forClaims);
        assertThat(targetAnnotations.forClaim()).contains(forClaim);
        assertThat(targetAnnotations.forPayload()).contains(forPayload);
    }
}