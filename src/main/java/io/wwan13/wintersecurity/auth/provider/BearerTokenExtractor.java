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

import io.wwan13.wintersecurity.auth.TokenExtractor;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

public class BearerTokenExtractor implements TokenExtractor {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_TOKEN_PREFIX = "Bearer ";

    public Optional<String> extract(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

        if (!hasToken(bearerToken) || !isValidTokenPrefix(bearerToken) || !containsToken(bearerToken)) {
            return Optional.empty();
        }

        String token = bearerToken.substring(BEARER_TOKEN_PREFIX.length());
        return Optional.of(token);
    }

    private boolean hasToken(String bearerToken) {
        return bearerToken != null && !bearerToken.isEmpty();
    }

    private boolean isValidTokenPrefix(String bearerToken) {
        return bearerToken.startsWith(BEARER_TOKEN_PREFIX);
    }

    private boolean containsToken(String bearerToken) {
        return bearerToken.length() > BEARER_TOKEN_PREFIX.length();
    }
}
