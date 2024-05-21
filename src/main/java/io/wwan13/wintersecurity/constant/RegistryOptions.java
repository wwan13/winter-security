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

import org.springframework.http.HttpMethod;

import java.util.Collections;
import java.util.Set;

import static org.springframework.http.HttpMethod.*;
import static org.springframework.http.HttpMethod.DELETE;

public class RegistryOptions {

    private RegistryOptions() {
        throw new IllegalStateException("Cannot instantiate a utility class!");
    }

    public static final Set<HttpMethod> ALL_HTTP_METHODS = Set.of(GET, POST, PATCH, PUT, DELETE);
    public static final Set<HttpMethod> HTTP_METHOD_GET = Collections.singleton(GET);
    public static final Set<HttpMethod> HTTP_METHOD_POST = Collections.singleton(POST);
    public static final Set<HttpMethod> HTTP_METHOD_PATCH = Collections.singleton(PATCH);
    public static final Set<HttpMethod> HTTP_METHOD_PUT = Collections.singleton(PUT);
    public static final Set<HttpMethod> HTTP_METHOD_DELETE = Collections.singleton(DELETE);

    public static final Set<Object> ALL_ROLES = Collections.singleton(DefaultAuthPattern.PERMIT_ALL);
    public static final Set<Object> EMPTY_ROLES = Collections.singleton(DefaultAuthPattern.AUTHENTICATED);

    public static final boolean DEFAULT_ELSE_REQUEST_OPTION = true;
}
