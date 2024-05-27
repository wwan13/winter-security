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

import io.wwan13.wintersecurity.resolve.*;

import java.lang.annotation.Annotation;
import java.util.HashSet;
import java.util.Set;

public class TargetAnnotationsRegistry {

    private final static Set<Class<? extends Annotation>> DEFAULT_SUBJECT_TARGETS
            = Set.of(RequestUserSubject.class, RequestUserId.class);
    private final static Set<Class<? extends Annotation>> DEFAULT_ROLES_TARGETS
            = Set.of(RequestUserRoles.class);
    private final static Set<Class<? extends Annotation>> DEFAULT_CLAIMS_TARGETS
            = Set.of(RequestUserClaims.class);
    private final static Set<Class<? extends Annotation>> DEFAULT_CLAIM_TARGETS
            = Set.of(RequestUserClaim.class);
    private final static Set<Class<? extends Annotation>> DEFAULT_PAYLOAD_TARGETS
            = Set.of(RequestUserPayload.class);

    private final Set<Class<? extends Annotation>> forSubject;
    private final Set<Class<? extends Annotation>> forRoles;
    private final Set<Class<? extends Annotation>> forClaims;
    private final Set<Class<? extends Annotation>> forClaim;
    private final Set<Class<? extends Annotation>> forPayload;

    public TargetAnnotationsRegistry() {
        this.forSubject = new HashSet<>(DEFAULT_SUBJECT_TARGETS);
        this.forRoles = new HashSet<>(DEFAULT_ROLES_TARGETS);
        this.forClaims = new HashSet<>(DEFAULT_CLAIMS_TARGETS);
        this.forClaim = new HashSet<>(DEFAULT_CLAIM_TARGETS);
        this.forPayload = new HashSet<>(DEFAULT_PAYLOAD_TARGETS);
    }

    public TargetAnnotationsRegistry addSubjectResolveAnnotation(
            Class<? extends Annotation> target
    ) {
        forSubject.add(target);
        return this;
    }

    public TargetAnnotationsRegistry addRolesResolveAnnotation(
            Class<? extends Annotation> target
    ) {
        forRoles.add(target);
        return this;
    }

    public TargetAnnotationsRegistry addClaimsResolveAnnotation(
            Class<? extends Annotation> target
    ) {
        forClaims.add(target);
        return this;
    }

    public TargetAnnotationsRegistry addClaimResolveAnnotation(
            Class<? extends Annotation> target
    ) {
        forClaim.add(target);
        return this;
    }

    public TargetAnnotationsRegistry addPayloadResolveAnnotation(
            Class<? extends Annotation> target
    ) {
        forPayload.add(target);
        return this;
    }

    protected TargetAnnotations apply() {
        return new TargetAnnotations(forSubject, forRoles, forClaims, forClaim, forPayload);
    }
}
