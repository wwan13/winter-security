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

package io.wwan13.wintersecurity.jwt.support;

import io.wwan13.wintersecurity.jwt.JwtProperties;
import io.wwan13.wintersecurity.jwt.Payload;

import java.util.Objects;

import static io.wwan13.wintersecurity.constant.Constants.DEFAULT_ACCESS_TOKEN_VALIDITY;
import static io.wwan13.wintersecurity.constant.Constants.DEFAULT_PAYLOAD_CLAZZ;
import static io.wwan13.wintersecurity.constant.Constants.DEFAULT_REFRESH_TOKEN_VALIDITY;
import static io.wwan13.wintersecurity.constant.Constants.DEFAULT_SUBJECT_CLAZZ;

public class JwtPropertiesRegistry {

    private long accessTokenValidity;
    private long refreshTokenValidity;
    private Class<? extends Payload> payloadClazz;
    private Class<?> subjectClazz;

    public JwtPropertiesRegistry accessTokenValidity(long accessTokenValidityInSecond) {
        this.accessTokenValidity = accessTokenValidityInSecond;
        return this;
    }

    public JwtPropertiesRegistry refreshTokenValidity(long refreshTokenValidityInSecond) {
        this.refreshTokenValidity = refreshTokenValidityInSecond;
        return this;
    }

    public JwtPropertiesRegistry payloadClazz(Class<? extends Payload> payloadClazz) {
        this.payloadClazz = payloadClazz;
        return this;
    }

    public JwtPropertiesRegistry subjectClazz(Class<?> subjectClazz) {
        this.subjectClazz = subjectClazz;
        return this;
    }

    protected JwtProperties apply() {
        return new JwtProperties(
                existOrDefaultValidity(accessTokenValidity, DEFAULT_ACCESS_TOKEN_VALIDITY),
                existOrDefaultValidity(refreshTokenValidity, DEFAULT_REFRESH_TOKEN_VALIDITY),
                existOrDefaultPayload(payloadClazz),
                existOrDefaultSubject(subjectClazz)
        );
    }

    private long existOrDefaultValidity(long validityInSecond, long defaultValidityInSecond) {
        if (validityInSecond == 0) {
            return defaultValidityInSecond;
        }
        return validityInSecond;
    }

    private Class<? extends Payload> existOrDefaultPayload(Class<? extends Payload> payloadClazz) {
        if (Objects.isNull(payloadClazz)) {
            return DEFAULT_PAYLOAD_CLAZZ;
        }
        return payloadClazz;
    }

    private Class<?> existOrDefaultSubject(Class<?> subjectClazz) {
        if (Objects.isNull(subjectClazz)) {
            return DEFAULT_SUBJECT_CLAZZ;
        }
        return subjectClazz;
    }
}
