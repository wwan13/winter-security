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

import io.wwan13.wintersecurity.constant.Constants;
import io.wwan13.wintersecurity.jwt.payload.util.RoleSerializer;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public record TokenClaims(
        Map<String, Object> claims
) {

    public Object getSubject() {
        return getValueWithNullChecking(Constants.DEFAULT_SUBJECT_KEY);
    }

    public Set<String> getRoles() {
        String rawRoles = (String) getValueWithNullChecking(Constants.PAYLOAD_KEY_USER_ROLE);
        return RoleSerializer.deserialize(rawRoles);
    }

    public boolean isAccessToken() {
        String tokenType = (String) getValueWithNullChecking(Constants.PAYLOAD_KEY_TOKEN_TYPE);
        return Constants.TOKEN_TYPE_ACCESS.equals(tokenType);
    }

    public boolean isRefreshToken() {
        String tokenType = (String) getValueWithNullChecking(Constants.PAYLOAD_KEY_TOKEN_TYPE);
        return Constants.TOKEN_TYPE_REFRESH.equals(tokenType);
    }

    public Object get(String key) {
        return getValueWithNullChecking(key);
    }

    public Map<String, Object> toMap() {
        return new HashMap<>(claims);
    }

    private Object getValueWithNullChecking(String key) {
        Object value = claims.get(key);
        if (Objects.isNull(value)) {
            throw new IllegalArgumentException(key + "not exists at token claims");
        }
        return value;
    }
}
