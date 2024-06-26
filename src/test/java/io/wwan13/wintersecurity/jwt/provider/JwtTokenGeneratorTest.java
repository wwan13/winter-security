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

import org.junit.jupiter.api.Test;

import static io.wwan13.wintersecurity.jwt.provider.ProviderTestContainer.tokenGenerator;
import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenGeneratorTest {

    @Test
    void should_CreateAccessToken() {
        // given
        final long id = 1L;
        final String role = "role";
        final String claim = "claim";
        Object payload = new ProviderTestContainer.TestPayload(id, role, claim);

        // when
        String accessToken = tokenGenerator.accessToken(payload);

        // then
        assertThat(accessToken).isNotEmpty();
    }

    @Test
    void should_CreateRefreshToken() {
        // given
        final long id = 1L;
        final String role = "role";
        final String claim = "claim";
        Object payload = new ProviderTestContainer.TestPayload(id, role, claim);

        // when
        String refreshToken = tokenGenerator.refreshToken(payload);

        // then
        assertThat(refreshToken).isNotEmpty();
    }
}