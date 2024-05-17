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
    public static final Class<?> DEFAULT_PAYLOAD_CLAZZ = DefaultPayload.class;
    public static final Class<?> DEFAULT_SUBJECT_CLAZZ = Object.class;

    // Payload
    public static final String PAYLOAD_TOKEN_TYPE = "PAYLOAD_TOKEN_TYPE";
    public static final String PAYLOAD_USER_ROLE = "PAYLOAD_USER_ROLE";

    // Token
    public static final String TOKEN_TYPE_ACCESS = "ACCESS_TOKEN";
    public static final String TOKEN_TYPE_REFRESH = "REFRESH_TOKEN";

    // Delimiter
    public static final String ROLE_DELIMITER = "&";

    private Constants() {
        throw new IllegalStateException("Cannot instantiate a utility class!");
    }
}
