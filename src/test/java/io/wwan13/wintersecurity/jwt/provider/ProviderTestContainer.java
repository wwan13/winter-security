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

package io.wwan13.wintersecurity.jwt.provider;

import io.wwan13.wintersecurity.jwt.*;
import io.wwan13.wintersecurity.jwt.payload.annotation.Claim;
import io.wwan13.wintersecurity.jwt.payload.annotation.Roles;
import io.wwan13.wintersecurity.jwt.payload.annotation.Subject;
import io.wwan13.wintersecurity.jwt.payload.support.JwtPayloadParser;
import io.wwan13.wintersecurity.jwt.payload.support.ReflectionPayloadAnalyst;
import io.wwan13.wintersecurity.jwt.support.JwtPropertiesApplier;
import io.wwan13.wintersecurity.jwt.support.JwtPropertiesRegistry;

public class ProviderTestContainer {

    public static class TestPayload implements Payload {
        @Subject
        long id;
        @Roles
        String role;
        @Claim
        String claim;

        public TestPayload(long id, String role, String claim) {
            this.id = id;
            this.role = role;
            this.claim = claim;
        }

        public TestPayload() {
        }

        public long getId() {
            return id;
        }

        public String getRole() {
            return role;
        }

        public String getClaim() {
            return claim;
        }
    }

    public static JwtProperties jwtProperties = JwtPropertiesApplier.apply(
            new JwtPropertiesRegistry()
                    .secretKey("secret-key-secret-key-secret-key-secret-key-secret-key-secret-key")
                    .accessTokenValidity(100000000000L)
                    .refreshTokenValidity(100000000000L)
                    .payloadClazz(TestPayload.class)
                    .subjectClazz(long.class)
    );

    public static PayloadAnalysis payloadAnalysis() {
        PayloadAnalyst payloadAnalyst = new ReflectionPayloadAnalyst();
        return payloadAnalyst.analyze(jwtProperties);
    }

    public static PayloadParser payloadParser = new JwtPayloadParser(payloadAnalysis());

    public static TokenGenerator tokenGenerator = new JwtTokenGenerator(jwtProperties, payloadParser);

    public static TokenDecoder tokenDecoder = new JwtTokenDecoder(jwtProperties);
}
