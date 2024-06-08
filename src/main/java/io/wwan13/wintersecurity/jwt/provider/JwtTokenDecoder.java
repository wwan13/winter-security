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
import io.wwan13.wintersecurity.exception.unauthirized.ExpiredJwtTokenException;
import io.wwan13.wintersecurity.exception.unauthirized.InvalidJwtTokenException;
import io.wwan13.wintersecurity.jwt.TokenClaims;
import io.wwan13.wintersecurity.jwt.TokenDecoder;
import io.wwan13.wintersecurity.secretkey.SecretKey;

import java.security.Key;
import java.util.Map;

public class JwtTokenDecoder implements TokenDecoder {

    private final SecretKey secretKey;

    public JwtTokenDecoder(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    public TokenClaims decode(String token) {
        Map<String, Object> claims = parseClaimsWithExceptionHandling(token);
        return new TokenClaims(claims);
    }

    public Claims parseClaimsWithExceptionHandling(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secretKey.value())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new ExpiredJwtTokenException();
        } catch (MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            throw new InvalidJwtTokenException();
        }
    }
}
