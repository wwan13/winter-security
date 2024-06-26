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

package io.wwan13.wintersecurity.exception;

import io.wwan13.wintersecurity.UnitTest;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class WinterSecurityExceptionTest extends UnitTest {

    @Test
    void should_ThrowException_when_HttpStatusAndMessageEntered() {
        // given
        final int httpStatus = 400;
        final String message = "error message";

        // when
        WinterSecurityException exception = new WinterSecurityException(httpStatus, message);

        // then
        assertThat(exception).isInstanceOf(WinterSecurityException.class);
        assertThat(exception.getHttpStatusCode()).isEqualTo(httpStatus);
        assertThat(exception.getMessage()).isEqualTo(message);
    }
}