package io.wwan13.wintersecurity.jwt.support;

import io.wwan13.wintersecurity.UnitTest;
import io.wwan13.wintersecurity.jwt.JwtProperties;
import io.wwan13.wintersecurity.jwt.payload.DefaultPayload;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JwtPropertiesApplierTest extends UnitTest {

    @Test
    void should_ReturnJwtProperties_when_RegistryEntered() {
        // given
        final String secretKey = "secretkey123123123123123123123123123123123123123123123123";
        final long accessTokenValidity = 1000L;
        final long refreshTokenValidity = 1000L;
        final Class<?> payloadClass = DefaultPayload.class;
        final Class<?> subjectClass = long.class;

        JwtPropertiesRegistry registry = new JwtPropertiesRegistry()
                .secretKey(secretKey)
                .accessTokenValidity(accessTokenValidity)
                .refreshTokenValidity(refreshTokenValidity)
                .payloadClazz(payloadClass)
                .subjectClazz(subjectClass);

        // when
        JwtProperties jwtProperties = JwtPropertiesApplier.apply(registry);

        // then
        assertThat(jwtProperties).isInstanceOf(JwtProperties.class);
        assertThat(jwtProperties.secretKey()).isEqualTo(secretKey);
        assertThat(jwtProperties.accessTokenValidity()).isEqualTo(accessTokenValidity);
        assertThat(jwtProperties.refreshTokenValidity()).isEqualTo(refreshTokenValidity);
        assertThat(jwtProperties.payloadClazz()).isEqualTo(payloadClass);
        assertThat(jwtProperties.subjectClazz()).isEqualTo(subjectClass);
    }
}