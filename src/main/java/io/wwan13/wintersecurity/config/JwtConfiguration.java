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

package io.wwan13.wintersecurity.config;

import io.wwan13.wintersecurity.jwt.JwtProperties;
import io.wwan13.wintersecurity.jwt.PayloadAnalysis;
import io.wwan13.wintersecurity.jwt.PayloadAnalyst;
import io.wwan13.wintersecurity.jwt.PayloadParser;
import io.wwan13.wintersecurity.jwt.PayloadScanner;
import io.wwan13.wintersecurity.jwt.TokenDecoder;
import io.wwan13.wintersecurity.jwt.TokenGenerator;
import io.wwan13.wintersecurity.jwt.payload.support.JwtPayloadParser;
import io.wwan13.wintersecurity.jwt.payload.support.DefaultPayloadAnalyst;
import io.wwan13.wintersecurity.jwt.payload.support.ReflectionPayloadScanner;
import io.wwan13.wintersecurity.jwt.provider.JwtTokenDecoder;
import io.wwan13.wintersecurity.jwt.provider.JwtTokenGenerator;
import io.wwan13.wintersecurity.secretkey.SecretKey;
import org.springframework.context.annotation.Bean;

public class JwtConfiguration {

    @Bean
    public TokenGenerator tokenGenerator(
            SecretKey secretKey,
            JwtProperties jwtProperties,
            PayloadParser payloadParser
    ) {
        return new JwtTokenGenerator(secretKey, jwtProperties, payloadParser);
    }

    @Bean
    public TokenDecoder tokenDecoder(SecretKey secretKey) {
        return new JwtTokenDecoder(secretKey);
    }

    @Bean
    public PayloadAnalysis payloadAnalysis(JwtProperties jwtProperties) {
        PayloadScanner payloadScanner = new ReflectionPayloadScanner();
        PayloadAnalyst payloadAnalyst = new DefaultPayloadAnalyst();

        Class<?> scannedPayload = payloadScanner.scan();
        return payloadAnalyst.analyze(scannedPayload);
    }

    @Bean
    public PayloadParser payloadParser(PayloadAnalysis payloadAnalysis) {
        return new JwtPayloadParser(payloadAnalysis);
    }
}
