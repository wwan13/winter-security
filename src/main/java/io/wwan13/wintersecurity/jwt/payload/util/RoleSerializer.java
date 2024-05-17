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

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static io.wwan13.wintersecurity.constant.Constants.ROLE_DELIMITER;

public class RoleSerializer {

    private RoleSerializer() {
        throw new IllegalStateException("Cannot instantiate a utility class!");
    }

    public static String serialize(Set<String> roles) {
        return String.join(ROLE_DELIMITER, roles);
    }

    public static Set<String> deserialize(String roles) {
        return Arrays.stream(roles.split(ROLE_DELIMITER))
                .collect(Collectors.toUnmodifiableSet());
    }
}
