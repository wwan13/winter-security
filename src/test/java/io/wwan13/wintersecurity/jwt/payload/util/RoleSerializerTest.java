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

package io.wwan13.wintersecurity.jwt.payload.util;

import io.wwan13.wintersecurity.UnitTest;
import io.wwan13.wintersecurity.constant.Constants;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RoleSerializerTest extends UnitTest {

    @Test
    void should_SerializeRolesWithDelimiter_when_ManyRolesEntered() {
        // given
        final String role1 = "role1";
        final String role2 = "role2";
        final Set<String> roles = Set.of(role1, role2);

        // when
        String result = RoleSerializer.serialize(roles);

        // then
        assertThat(result).isInstanceOf(String.class)
                .contains(Constants.ROLE_DELIMITER, role1, role2);
    }

    @Test
    void should_DeserializeRolesToStringSet_when_SerializedRolesEntered() {
        // given
        final String role1 = "role1";
        final String role2 = "role2";
        final String serializedRoles = role1 + Constants.ROLE_DELIMITER + role2;

        // when
        Set<String> result = RoleSerializer.deserialize(serializedRoles);

        // then
        assertThat(result).isInstanceOf(Set.class)
                .contains(role1, role2);
    }
}