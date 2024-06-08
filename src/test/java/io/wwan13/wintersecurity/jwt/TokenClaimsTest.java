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

package io.wwan13.wintersecurity.jwt;

import io.wwan13.wintersecurity.UnitTest;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenClaimsTest extends UnitTest {

    static final Map<String, Object> defaultClaims = Map.of(
            "sub", "subject",
            "roles", "ROLE_USER&ROLE_ADMIN",
            "token_type", "refresh_token"
    );

    static final Map<String, Object> emptyClaims = Map.of();

    @Test
    void should_ContainsSubject() {
        // given
        final TokenClaims tokenClaims = new TokenClaims(defaultClaims);

        // when
        Object subject = tokenClaims.getSubject();

        // then
        assertThat((String) subject).isEqualTo(defaultClaims.get("sub"));
    }

    @Test
    void should_ThrowException_when_SubjectNotExists() {
        // given
        final TokenClaims tokenClaims = new TokenClaims(emptyClaims);

        // when, then
        assertThatThrownBy(tokenClaims::getSubject)
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void should_ContainsRoles() {
        // given
        final TokenClaims tokenClaims = new TokenClaims(defaultClaims);

        // when
        Set<String> subject = tokenClaims.getRoles();

        // then
        assertThat(subject).contains("ROLE_ADMIN", "ROLE_USER");
    }

    @Test
    void should_ThrowException_when_RolesNotExists() {
        // given
        final TokenClaims tokenClaims = new TokenClaims(emptyClaims);

        // when, then
        assertThatThrownBy(tokenClaims::getRoles)
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void should_JudgeTokenType() {
        // given
        final TokenClaims tokenClaims = new TokenClaims(defaultClaims);

        // when
        boolean isAccessToken = tokenClaims.isAccessToken();
        boolean isRefreshToken = tokenClaims.isRefreshToken();

        // then
        assertThat(isAccessToken).isFalse();
        assertThat(isRefreshToken).isTrue();
    }
}