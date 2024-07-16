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

package io.wwan13.wintersecurity.auth.processor;

import io.wwan13.wintersecurity.auth.RequestAccessManager;
import io.wwan13.wintersecurity.auth.RequestStorage;
import io.wwan13.wintersecurity.auth.TokenExtractor;
import io.wwan13.wintersecurity.constant.Constants;
import io.wwan13.wintersecurity.exception.unauthirized.ExpiredJwtTokenException;
import io.wwan13.wintersecurity.exception.unauthirized.InvalidJwtTokenException;
import io.wwan13.wintersecurity.jwt.TokenClaims;
import io.wwan13.wintersecurity.jwt.TokenDecoder;
import org.springframework.http.HttpMethod;

import javax.servlet.http.HttpServletRequest;

public class InterceptorAuthProcessor extends AbstractInterceptorAuthProcessor {

    private final TokenExtractor tokenExtractor;
    private final TokenDecoder tokenDecoder;
    private final RequestAccessManager accessManager;

    public InterceptorAuthProcessor(
            TokenExtractor tokenExtractor,
            TokenDecoder tokenDecoder,
            RequestAccessManager accessManager
    ) {
        this.tokenExtractor = tokenExtractor;
        this.tokenDecoder = tokenDecoder;
        this.accessManager = accessManager;
    }

    @Override
    public void processInternal(HttpServletRequest request, RequestStorage storage) {
        tokenExtractor.extract(request)
                .ifPresentOrElse(
                        token -> actionIfTokenPresent(token, request, storage),
                        () -> actionIfTokenAbsent(request)
                );
    }

    private void actionIfTokenPresent(
            String token,
            HttpServletRequest request,
            RequestStorage storage
    ) {
        try {
            TokenClaims claims = tokenDecoder.decode(token);

            accessManager.manageWithAuthentication(
                    HttpMethod.resolve(request.getMethod()),
                    request.getRequestURI(),
                    claims.getRoles()
            );

            storage.save(Constants.ATTRIBUTE_CLAIMS_KEY, claims);
        } catch (InvalidJwtTokenException | ExpiredJwtTokenException e) {
            HttpMethod method = HttpMethod.resolve(request.getMethod());
            String uri = request.getRequestURI();

            if (!accessManager.isUnsecuredRequest(method, uri)) {
                throw e;
            }
        }
    }

    private void actionIfTokenAbsent(HttpServletRequest request) {
        accessManager.manageWithoutAuthentication(
                HttpMethod.resolve(request.getMethod()),
                request.getRequestURI()
        );
    }
}