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

package io.wwan13.wintersecurity.auth.authorizedrequest.support;

import io.wwan13.wintersecurity.auth.authorizedrequest.Permissions;
import io.wwan13.wintersecurity.auth.authorizedrequest.AuthorizedRequest;
import io.wwan13.wintersecurity.auth.authorizedrequest.Requests;
import io.wwan13.wintersecurity.constant.RegistryOptions;
import org.springframework.http.HttpMethod;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthorizedRequestRegistry {

    private final Map<Requests, Permissions> registered;
    private boolean isElseRequestPermit;

    public AuthorizedRequestRegistry(
            Map<Requests, Permissions> registered,
            boolean isElseRequestPermit
    ) {
        this.registered = registered;
        this.isElseRequestPermit = isElseRequestPermit;
    }

    public static AuthorizedRequestRegistry of() {
        return new AuthorizedRequestRegistry(
                new LinkedHashMap<>(),
                RegistryOptions.DEFAULT_ELSE_REQUEST_OPTION
        );
    }

    public HttpMethodAppender uriPatterns(String... uriPatterns) {
        return new HttpMethodAppender(this, Set.of(uriPatterns));
    }

    public void elseRequestPermit() {
        this.isElseRequestPermit = true;
    }

    public void elseRequestAuthenticated() {
        this.isElseRequestPermit = false;
    }

    protected AuthorizedRequest apply() {
        return new AuthorizedRequest(registered, isElseRequestPermit);
    }

    public static class HttpMethodAppender {

        private final AuthorizedRequestRegistry registry;
        private final Set<String> uriPatterns;

        HttpMethodAppender(AuthorizedRequestRegistry registry, Set<String> uriPatterns) {
            this.registry = registry;
            this.uriPatterns = uriPatterns;
        }

        public RolesAppender httpMethods(HttpMethod... methods) {
            return new RolesAppender(registry, uriPatterns, Set.of(methods));
        }

        public RolesAppender allHttpMethods() {
            return new RolesAppender(registry, uriPatterns, RegistryOptions.ALL_HTTP_METHODS);
        }

        public RolesAppender httpMethodGet() {
            return new RolesAppender(registry, uriPatterns, RegistryOptions.HTTP_METHOD_GET);
        }

        public RolesAppender httpMethodPost() {
            return new RolesAppender(registry, uriPatterns, RegistryOptions.HTTP_METHOD_POST);
        }

        public RolesAppender httpMethodPatch() {
            return new RolesAppender(registry, uriPatterns, RegistryOptions.HTTP_METHOD_PATCH);
        }

        public RolesAppender httpMethodPut() {
            return new RolesAppender(registry, uriPatterns, RegistryOptions.HTTP_METHOD_PUT);
        }

        public RolesAppender httpMethodDelete() {
            return new RolesAppender(registry, uriPatterns, RegistryOptions.HTTP_METHOD_DELETE);
        }
    }

    public static class RolesAppender {

        private final AuthorizedRequestRegistry registry;
        private final Set<String> uriPatterns;
        private final Set<HttpMethod> httpMethods;

        RolesAppender(
                AuthorizedRequestRegistry registry,
                Set<String> uriPatterns,
                Set<HttpMethod> httpMethods
        ) {
            this.registry = registry;
            this.uriPatterns = uriPatterns;
            this.httpMethods = httpMethods;
        }

        public AuthorizedRequestRegistry permitAll() {
            appendRolesPerPattern(RegistryOptions.ALL_ROLES);
            return registry;
        }

        public AuthorizedRequestRegistry authenticated() {
            appendRolesPerPattern(RegistryOptions.EMPTY_ROLES);
            return registry;
        }

        public AuthorizedRequestRegistry hasRoles(Object... roles) {
            appendRolesPerPattern(Set.of(roles));
            return registry;
        }

        private void appendRolesPerPattern(Set<Object> roles) {
            uriPatterns.forEach(
                    pattern -> registry.registered.put(
                            new Requests(httpMethods, pattern),
                            mapRoles(roles)
                    )
            );
        }

        private Permissions mapRoles(Set<Object> roles) {
            return new Permissions(
                    roles.stream()
                            .map(Object::toString)
                            .collect(Collectors.toUnmodifiableSet())
            );
        }
    }
}
