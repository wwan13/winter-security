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

package io.wwan13.wintersecurity.context;

import io.wwan13.wintersecurity.ContextTest;
import io.wwan13.wintersecurity.auth.authorizedrequest.AuthorizedRequest;
import io.wwan13.wintersecurity.context.config.TestContextConfig;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@Deprecated
@Import({TestContextConfig.class})
public class AuthorizedRequestContextTest extends ContextTest {

    @Autowired
    AuthorizedRequest authorizedRequest;

    @ParameterizedTest
    @CsvSource({
            "GET, /api/test/hello, ROLE_ADMIN, true",
            "GET, /api/bad/hello, ROLE_ADMIN, false",
    })
    void should_RegisteredInSpringIocWithEnteredValue_when_ContextLoaded(
            final String requestMethod,
            final String requestUri,
            final String requestRole,
            final boolean expected
    ) {
        // given, when
        boolean result = authorizedRequest
                .isAccessibleRequest(HttpMethod.resolve(requestMethod), requestUri, Set.of(requestRole));

        // then
        assertThat(result).isEqualTo(expected);
    }
}
