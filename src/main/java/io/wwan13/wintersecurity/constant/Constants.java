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

package io.wwan13.wintersecurity.constant;

import io.wwan13.wintersecurity.jwt.payload.DefaultPayload;

public class Constants {

    // Default Option
    public static final long DEFAULT_ACCESS_TOKEN_VALIDITY = 10000;
    public static final long DEFAULT_REFRESH_TOKEN_VALIDITY = 10000;

    // Payload
    public static final String PAYLOAD_KEY_TOKEN_TYPE = "token_type";
    public static final String PAYLOAD_KEY_USER_ROLE = "roles";
    public static final String DEFAULT_SUBJECT_KEY = "sub";

    // Attribute
    public static final String ATTRIBUTE_CLAIMS_KEY = "claims";

    // Token
    public static final String TOKEN_TYPE_ACCESS = "access_token";
    public static final String TOKEN_TYPE_REFRESH = "refresh_token";

    // Delimiter
    public static final String ROLE_DELIMITER = "&";

    private Constants() {
        throw new IllegalStateException("Cannot instantiate a utility class!");
    }
}
