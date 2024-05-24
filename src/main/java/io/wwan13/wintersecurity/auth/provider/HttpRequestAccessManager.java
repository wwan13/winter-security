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

package io.wwan13.wintersecurity.auth.provider;

import io.wwan13.wintersecurity.auth.RequestAccessManager;
import io.wwan13.wintersecurity.auth.authorizedrequest.AuthorizedRequest;
import io.wwan13.wintersecurity.constant.DefaultAuthPattern;
import io.wwan13.wintersecurity.exception.forbidden.ForbiddenException;
import io.wwan13.wintersecurity.exception.unauthirized.UnauthorizedException;
import org.springframework.http.HttpMethod;

public class HttpRequestAccessManager implements RequestAccessManager {

    private final AuthorizedRequest authorizedRequest;

    public HttpRequestAccessManager(AuthorizedRequest authorizedRequest) {
        this.authorizedRequest = authorizedRequest;
    }

    public void manageWithAuthentication(HttpMethod method, String uri, String role) {
        if (!authorizedRequest.isAccessibleRequest(method, uri, role)) {
            throw new ForbiddenException();
        }
    }

    public void manageWithoutAuthentication(HttpMethod method, String uri) {
        String role = DefaultAuthPattern.ANONYMOUS_ROLE;

        if (!authorizedRequest.isAccessibleRequest(method, uri, role)) {
            throw new UnauthorizedException();
        }
    }
}
