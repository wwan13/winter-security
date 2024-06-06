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

package io.wwan13.wintersecurity.secretkey.support;

import io.wwan13.wintersecurity.UnitTest;
import io.wwan13.wintersecurity.secretkey.SecretKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.Key;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class SecretKeyRegistryTest extends UnitTest {

    @Test
    void should_ContainsSecretKey() {
        // given
        final String secretKey = "secretkey123123123123123123123123123123123123123123123123";

        // when
        SecretKey result = new SecretKeyRegistry()
                .secretKey(secretKey)
                .apply();

        // then
        assertThat(result.value()).isInstanceOf(Key.class);
    }

    @ParameterizedTest(name = "{index} : {0}")
    @NullAndEmptySource
    @ValueSource(strings = {
            "short secret key",
            "1234567890123456789012345678901"
    })
    void should_ThrowsException_when_SecretKeyIsEmptyOrLessThen32(final String secretKey) {
        // given
        SecretKeyRegistry registry = new SecretKeyRegistry()
                .secretKey(secretKey);

        // when, then
        assertThatThrownBy(registry::apply)
                .isInstanceOf(IllegalArgumentException.class);
    }
}