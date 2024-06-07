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

import static io.wwan13.wintersecurity.constant.Constants.DEFAULT_ACCESS_TOKEN_VALIDITY;
import static io.wwan13.wintersecurity.constant.Constants.DEFAULT_REFRESH_TOKEN_VALIDITY;

public class JwtPropertiesRegistry {

    private long accessTokenValidity;
    private long refreshTokenValidity;

    public JwtPropertiesRegistry accessTokenValidity(long accessTokenValidityInSecond) {
        this.accessTokenValidity = accessTokenValidityInSecond;
        return this;
    }

    public JwtPropertiesRegistry refreshTokenValidity(long refreshTokenValidityInSecond) {
        this.refreshTokenValidity = refreshTokenValidityInSecond;
        return this;
    }

    protected JwtProperties apply() {
        return new JwtProperties(
                existOrDefaultValidity(accessTokenValidity, DEFAULT_ACCESS_TOKEN_VALIDITY),
                existOrDefaultValidity(refreshTokenValidity, DEFAULT_REFRESH_TOKEN_VALIDITY)
        );
    }

    private long existOrDefaultValidity(long validityInSecond, long defaultValidityInSecond) {
        if (validityInSecond == 0) {
            return defaultValidityInSecond;
        }
        return validityInSecond;
    }
}
