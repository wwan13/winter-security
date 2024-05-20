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

package io.wwan13.wintersecurity.jwt.provider;

import io.jsonwebtoken.Jwts;
import io.wwan13.wintersecurity.jwt.JwtProperties;
import io.wwan13.wintersecurity.jwt.Payload;
import io.wwan13.wintersecurity.jwt.PayloadParser;
import io.wwan13.wintersecurity.jwt.TokenGenerator;
import io.wwan13.wintersecurity.jwt.payload.util.RoleSerializer;
import io.wwan13.wintersecurity.util.DateUtil;

import static io.wwan13.wintersecurity.constant.Constants.*;

public class JwtTokenGenerator implements TokenGenerator {

    private final JwtProperties properties;
    private final PayloadParser payloadParser;

    public JwtTokenGenerator(JwtProperties properties, PayloadParser payloadParser) {
        this.properties = properties;
        this.payloadParser = payloadParser;
    }

    @Override
    public String accessToken(Payload payload) {
        validatePayloadClazz(payload.getClass());
        return Jwts.builder()
                .setSubject(payloadParser.asSubject(payload))
                .setIssuedAt(DateUtil.now())
                .setExpiration(DateUtil.addFromNow(properties.accessTokenValidity()))
                .claim(PAYLOAD_KEY_TOKEN_TYPE, TOKEN_TYPE_ACCESS)
                .claim(PAYLOAD_KEY_USER_ROLE, RoleSerializer.serialize(payloadParser.asRoles(payload)))
                .addClaims(payloadParser.asAdditionalClaims(payload))
                .signWith(properties.key())
                .compact();
    }

    @Override
    public String refreshToken(Payload payload) {
        validatePayloadClazz(payload.getClass());
        return Jwts.builder()
                .setSubject(payloadParser.asSubject(payload))
                .setIssuedAt(DateUtil.now())
                .setExpiration(DateUtil.addFromNow(properties.refreshTokenValidity()))
                .claim(PAYLOAD_KEY_TOKEN_TYPE, TOKEN_TYPE_REFRESH)
                .claim(PAYLOAD_KEY_USER_ROLE, RoleSerializer.serialize(payloadParser.asRoles(payload)))
                .addClaims(payloadParser.asAdditionalClaims(payload))
                .signWith(properties.key())
                .compact();
    }

    private void validatePayloadClazz(Class<? extends Payload> clazz) {
        if (!clazz.equals(properties.payloadClazz())) {
            throw new IllegalArgumentException("The type of payload between set and entered do not match.");
        }
    }
}
