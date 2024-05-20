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

import io.jsonwebtoken.*;
import io.wwan13.wintersecurity.exception.unauthirized.UnauthorizedErrorCode;
import io.wwan13.wintersecurity.exception.unauthirized.UnauthorizedException;
import io.wwan13.wintersecurity.jwt.JwtProperties;
import io.wwan13.wintersecurity.jwt.TokenDecoder;

import java.util.Map;

public class JwtTokenDecoder implements TokenDecoder {

    private final JwtProperties jwtProperties;

    public JwtTokenDecoder(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    @Override
    public Map<String, Object> decode(String token) {
        return parseClaimsWithExceptionHandling(token);
    }

    public Claims parseClaimsWithExceptionHandling(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(jwtProperties.key())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new UnauthorizedException(UnauthorizedErrorCode.EXPIRED_JWT_TOKEN);
        } catch (MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            throw new UnauthorizedException(UnauthorizedErrorCode.INVALID_JWT_TOKEN);
        }
    }
}
