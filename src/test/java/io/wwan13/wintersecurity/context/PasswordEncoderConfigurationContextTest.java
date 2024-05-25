package io.wwan13.wintersecurity.context;

import io.wwan13.wintersecurity.ContextTest;
import io.wwan13.wintersecurity.context.config.TestContextConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

@Import(TestContextConfig.class)
public class PasswordEncoderConfigurationContextTest extends ContextTest {

    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    void should_RegisteredInSpringIocWithEnteredValue_when_ContextLoaded() {
        // given, then, then
        assertThat(passwordEncoder)
                .isInstanceOf(PasswordEncoder.class)
                .isExactlyInstanceOf(BCryptPasswordEncoder.class);
    }
}
