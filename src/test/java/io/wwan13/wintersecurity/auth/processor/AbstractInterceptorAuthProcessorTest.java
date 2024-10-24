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

import io.wwan13.wintersecurity.UnitTest;
import io.wwan13.wintersecurity.auth.RequestStorage;
import io.wwan13.wintersecurity.auth.stub.StubHttpServletRequest;
import io.wwan13.wintersecurity.auth.stub.StubHttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.web.servlet.HandlerInterceptor;

import static org.assertj.core.api.Assertions.assertThat;

class AbstractInterceptorAuthProcessorTest extends UnitTest {

    static class StubAbstractInterceptorAuthProcessor extends AbstractInterceptorAuthProcessor {
        @Override
        protected void processInternal(HttpServletRequest request, RequestStorage storage) {
            final String key = "key";
            final String value = "value";
            storage.save(key, value);
        }
    }

    @Test
    void should_ExecutedByInterceptorPreHandleMethod() throws Exception {
        // given
        final HttpServletRequest request = new StubHttpServletRequest();
        final HttpServletResponse response = new StubHttpServletResponse();
        HandlerInterceptor interceptor = new StubAbstractInterceptorAuthProcessor();

        // when
        interceptor.preHandle(request, response, "object");

        // then
        assertThat(request.getAttribute("key")).isEqualTo("value");
    }
}