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

package io.wwan13.wintersecurity.auth;

import io.wwan13.wintersecurity.UnitTest;
import io.wwan13.wintersecurity.auth.stub.StubHttpServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class RequestStorageTest extends UnitTest {

    @Test
    void should_CreateHashMapStorage_when_CreatedByFactoryMethod() {
        // given, when
        final RequestStorage storage = RequestStorage.of();

        // then
        assertThat(storage.storage())
                .isInstanceOf(HashMap.class);
    }

    @Test
    void should_SaveItem() {
        // given
        final String key = "key";
        final String value = "value";
        final RequestStorage storage = RequestStorage.of();

        // when
        storage.save(key, value);

        // then
        assertThat(storage.storage().containsKey(key))
                .isTrue();
    }

    @Test
    void should_SaveAllItems() {
        // given
        final String key1 = "key1";
        final String key2 = "key2";
        final String value1 = "value1";
        final String value2 = "value2";
        final Map<String, Object> items = Map.of(key1, value1, key2, value2);
        final RequestStorage storage = RequestStorage.of();

        // when
        storage.saveAll(items);

        // then
        assertThat(storage.storage().keySet())
                .contains(key1, key2);
    }

    @Test
    void should_ConvertToRequestAttribute() {
        // given
        final String key = "key";
        final String value = "value";
        final RequestStorage storage = RequestStorage.of();
        storage.save(key, value);
        HttpServletRequest request = new StubHttpServletRequest();

        // when
        storage.toRequestAttribute(request);

        // then
        assertThat(request.getAttribute(key)).isEqualTo(value);
    }
}