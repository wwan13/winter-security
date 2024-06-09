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

package io.wwan13.wintersecurity.resolve.util;

import io.wwan13.wintersecurity.constant.Constants;
import io.wwan13.wintersecurity.jwt.TokenClaims;

import javax.servlet.http.HttpServletRequest;
import java.util.Objects;

public class AttributeExtractor {

    private AttributeExtractor() {
        throw new IllegalStateException("Cannot instantiate a utility class!");
    }

    public static Object extract(
            HttpServletRequest request,
            String attributeKey
    ) {
        return extractAttributeWithNullChecking(request, attributeKey);
    }

    public static TokenClaims extractClaims(HttpServletRequest request) {
        return (TokenClaims) extractAttributeWithNullChecking(request, Constants.ATTRIBUTE_CLAIMS_KEY);
    }

    private static Object extractAttributeWithNullChecking(
            HttpServletRequest request,
            String attributeKey
    ) {
        Object claims = request.getAttribute(attributeKey);
        if (Objects.isNull(claims)) {
            throw new IllegalStateException("cannot extract claims");
        }
        return claims;
    }
}
