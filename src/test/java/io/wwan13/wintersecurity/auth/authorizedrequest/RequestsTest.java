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

package io.wwan13.wintersecurity.auth.authorizedrequest;

import io.wwan13.wintersecurity.UnitTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpMethod;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RequestsTest extends UnitTest {

    @Test
    void should_HaveMethodsAndUriPattern() {
        // given
        final HttpMethod getMethod = HttpMethod.GET;
        final HttpMethod postMethod = HttpMethod.POST;
        final Set<HttpMethod> methods = Set.of(getMethod, postMethod);
        final String uriPattern = "/api/test/**";

        // when
        Requests requests = new Requests(methods, uriPattern);

        // then
        assertThat(requests).isInstanceOf(Requests.class);
        assertThat(requests.methods()).contains(getMethod, postMethod);
        assertThat(requests.uriPattern()).isEqualTo(uriPattern);
    }

    @ParameterizedTest
    @CsvSource({
            "GET, /api/test/good, true",
            "POST, /api/test/great, true",
            "DELETE, /api/test/bad, false",
            "GET, /api/cool/unhappy, false"
    })
    void should_JudgeRequestIsRegistered_when_MethodAndUriEntered(
            final String method,
            final String uri,
            final boolean expected
    ) {
        // given
        final HttpMethod getMethod = HttpMethod.GET;
        final HttpMethod postMethod = HttpMethod.POST;
        final Set<HttpMethod> methods = Set.of(getMethod, postMethod);
        final String uriPattern = "/api/test/**";
        Requests requests = new Requests(methods, uriPattern);

        // when
        boolean result = requests.isRegistered(HttpMethod.resolve(method), uri);

        // then
        assertThat(result).isEqualTo(expected);
    }
}