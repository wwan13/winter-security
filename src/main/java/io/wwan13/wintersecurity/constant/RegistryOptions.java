package io.wwan13.wintersecurity.constant;

import org.springframework.http.HttpMethod;

import java.util.Collections;
import java.util.Set;

import static org.springframework.http.HttpMethod.*;
import static org.springframework.http.HttpMethod.DELETE;

public class RegistryOptions {

    private RegistryOptions() {
        throw new IllegalStateException("Cannot instantiate a utility class!");
    }

    public static final Set<HttpMethod> ALL_HTTP_METHODS = Set.of(GET, POST, PATCH, PUT, DELETE);
    public static final Set<HttpMethod> HTTP_METHOD_GET = Collections.singleton(GET);
    public static final Set<HttpMethod> HTTP_METHOD_POST = Collections.singleton(POST);
    public static final Set<HttpMethod> HTTP_METHOD_PATCH = Collections.singleton(PATCH);
    public static final Set<HttpMethod> HTTP_METHOD_PUT = Collections.singleton(PUT);
    public static final Set<HttpMethod> HTTP_METHOD_DELETE = Collections.singleton(DELETE);

    public static final Set<Object> ALL_ROLES = Collections.singleton(DefaultAuthPattern.PERMIT_ALL);
    public static final Set<Object> EMPTY_ROLES = Collections.singleton(DefaultAuthPattern.AUTHENTICATED);

    public static final boolean DEFAULT_ELSE_REQUEST_OPTION = true;
}
