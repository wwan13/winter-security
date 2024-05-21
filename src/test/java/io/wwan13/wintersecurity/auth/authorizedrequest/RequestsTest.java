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