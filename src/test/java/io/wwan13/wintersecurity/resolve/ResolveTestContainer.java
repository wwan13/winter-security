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

import io.wwan13.wintersecurity.jwt.PayloadAnalysis;
import io.wwan13.wintersecurity.jwt.PayloadAnalyst;
import io.wwan13.wintersecurity.jwt.TokenClaims;
import io.wwan13.wintersecurity.jwt.payload.annotation.Roles;
import io.wwan13.wintersecurity.jwt.payload.annotation.Subject;
import io.wwan13.wintersecurity.jwt.payload.support.DefaultPayloadAnalyst;

import java.util.Map;
import java.util.Set;

public class ResolveTestContainer {

    public static TargetAnnotations targetAnnotations = new TargetAnnotations(
            Set.of(RequestUserSubject.class, RequestUserId.class),
            Set.of(RequestUserRoles.class)
    );

    public static PayloadAnalysis payloadAnalysis;

    static {
        PayloadAnalyst payloadAnalyst = new DefaultPayloadAnalyst();
        payloadAnalysis = payloadAnalyst.analyze(ResolveTestPayload.class);
    }

    public static TokenClaims defaultTestClaims = new TokenClaims(
            Map.of(
                    "sub", "1",
                    "roles", "ROLE_USER"
            )
    );

    public static class ResolveTestPayload {
        @Subject
        Long subject;
        @Roles
        Set<String> roles;
    }

    public static class ResolveTestPayloadWithStringRole {
        @Subject
        Long subject;
        @Roles
        String role;
    }
}
