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

package io.wwan13.wintersecurity.resolve.support;

import io.wwan13.wintersecurity.UnitTest;
import io.wwan13.wintersecurity.resolve.RequestUserClaim;
import io.wwan13.wintersecurity.resolve.RequestUserClaims;
import io.wwan13.wintersecurity.resolve.RequestUserId;
import io.wwan13.wintersecurity.resolve.RequestUserPayload;
import io.wwan13.wintersecurity.resolve.RequestUserRoles;
import io.wwan13.wintersecurity.resolve.RequestUserSubject;
import io.wwan13.wintersecurity.resolve.TargetAnnotations;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;

import static org.assertj.core.api.Assertions.assertThat;

class TargetAnnotationsRegistryTest extends UnitTest {

    @Test
    void should_CreateTargetAnnotationsObject_when_Apply() {
        // given
        final Class<? extends Annotation> forSubject = RequestUserSubject.class;
        final Class<? extends Annotation> forRoles = RequestUserRoles.class;
        final Class<? extends Annotation> forClaims = RequestUserClaims.class;
        final Class<? extends Annotation> forClaim = RequestUserClaim.class;
        final Class<? extends Annotation> forPayload = RequestUserPayload.class;

        TargetAnnotationsRegistry registry = new TargetAnnotationsRegistry();
        registry
                .addSubjectResolveAnnotation(forSubject)
                .addRolesResolveAnnotation(forRoles)
                .addClaimsResolveAnnotation(forClaims)
                .addClaimResolveAnnotation(forClaim)
                .addPayloadResolveAnnotation(forPayload);

        // when
        TargetAnnotations targetAnnotations = registry.apply();

        // then
        assertThat(targetAnnotations).isInstanceOf(TargetAnnotations.class);
        assertThat(targetAnnotations.forSubject()).contains(forSubject);
        assertThat(targetAnnotations.forRoles()).contains(forRoles);
        assertThat(targetAnnotations.forClaims()).contains(forClaims);
        assertThat(targetAnnotations.forClaim()).contains(forClaim);
        assertThat(targetAnnotations.forPayload()).contains(forPayload);
    }

    @Test
    void should_ContainsDefaultTargetAnnotations_when_NotingEntered() {
        // given
        TargetAnnotationsRegistry registry = new TargetAnnotationsRegistry();

        // when
        TargetAnnotations targetAnnotations = registry.apply();

        // then
        assertThat(targetAnnotations.forSubject())
                .contains(RequestUserSubject.class, RequestUserId.class);
        assertThat(targetAnnotations.forRoles()).contains(RequestUserRoles.class);
        assertThat(targetAnnotations.forClaims()).contains(RequestUserClaims.class);
        assertThat(targetAnnotations.forClaim()).contains(RequestUserClaim.class);
        assertThat(targetAnnotations.forPayload()).contains(RequestUserPayload.class);
    }
}