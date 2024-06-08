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

    private final Set<Class<? extends Annotation>> forSubject;
    private final Set<Class<? extends Annotation>> forRoles;

    public TargetAnnotationsRegistry() {
        this.forSubject = new HashSet<>(DEFAULT_SUBJECT_TARGETS);
        this.forRoles = new HashSet<>(DEFAULT_ROLES_TARGETS);
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

    protected TargetAnnotations apply() {
        return new TargetAnnotations(forSubject, forRoles);
    }
}
