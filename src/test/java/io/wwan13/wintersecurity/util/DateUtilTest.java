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

package io.wwan13.wintersecurity.util;

import io.wwan13.wintersecurity.UnitTest;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class DateUtilTest extends UnitTest {

    @Test
    void should_GetCurrentDate() {
        // given, when
        final Date date = DateUtil.now();

        // then
        assertThat(date).isInstanceOf(Date.class);
        assertThat(date.getTime()).isNotZero();
    }

    @Test
    void should_GetAddedDate() {
        // given
        final long addValue = 10000L;

        // when
        final Date date = DateUtil.addFromNow(addValue);

        // then
        assertThat(date).isInstanceOf(Date.class);
        assertThat(date).isAfter(DateUtil.now());
        assertThat(date.getTime()).isNotZero();
    }
}