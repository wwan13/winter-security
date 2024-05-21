package io.wwan13.wintersecurity.constant;

public class DefaultAuthPattern {

    private DefaultAuthPattern() {
        throw new IllegalStateException("Cannot instantiate a utility class!");
    }

    public static final String PERMIT_ALL = "*";
    public static final String AUTHENTICATED = "-";
    public static final String ANONYMOUS_ROLE = "ROLE_ANONYMOUS";
}
