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

package io.wwan13.wintersecurity.resolve;

import io.wwan13.wintersecurity.jwt.TokenClaims;
import io.wwan13.wintersecurity.resolve.util.AttributeExtractor;
import io.wwan13.wintersecurity.resolve.util.ResolveTypeConverter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.util.Collection;

public class RolesResolver implements HandlerMethodArgumentResolver {

    private final TargetAnnotations targetAnnotations;

    public RolesResolver(TargetAnnotations targetAnnotations) {
        this.targetAnnotations = targetAnnotations;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return targetAnnotations.forRoles().stream()
                .anyMatch(parameter::hasParameterAnnotation);
    }

    @Override
    public Object resolveArgument(
            MethodParameter parameter,
            ModelAndViewContainer mavContainer,
            NativeWebRequest webRequest,
            WebDataBinderFactory binderFactory
    ) {
        HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();

        TokenClaims claims = AttributeExtractor.extractClaims(request);

        boolean isCollection = Collection.class.isAssignableFrom(parameter.getParameterType());
        if (!isCollection) {
            String role = claims.getRoles().stream()
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("Empty role entered"));

            return ResolveTypeConverter.convertTo(role, parameter.getParameterType());
        }

        return ResolveTypeConverter.convertTo(claims.getRoles(), parameter.getParameterType());
    }
}
