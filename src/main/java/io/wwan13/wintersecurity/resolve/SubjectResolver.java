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
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpServletRequest;

public class SubjectResolver implements HandlerMethodArgumentResolver {

    private final TargetAnnotations targetAnnotations;

    public SubjectResolver(
            TargetAnnotations targetAnnotations
    ) {
        this.targetAnnotations = targetAnnotations;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return targetAnnotations.forSubject().stream()
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

        return ResolveTypeConverter.convertTo(
                claims.getSubject(),
                parameter.getParameterType()
        );
    }
}
