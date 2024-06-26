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

package io.wwan13.wintersecurity.jwt.payload.support;

import io.wwan13.wintersecurity.jwt.payload.annotation.Roles;
import io.wwan13.wintersecurity.jwt.payload.annotation.Subject;

import java.util.Set;

public class TestJwtPayloads {

    static class JwtPayloadWithWrapperClassSubject {
        @Subject
        Long subject;
        @Roles
        Set<String> roles;

        public JwtPayloadWithWrapperClassSubject(Long subject, Set<String> roles) {
            this.subject = subject;
            this.roles = roles;
        }
    }

    static class JwtPayloadWithDataTypeSubject {
        @Subject
        long subject;
        @Roles
        Set<String> roles;

        public JwtPayloadWithDataTypeSubject(long subject, Set<String> roles) {
            this.subject = subject;
            this.roles = roles;
        }
    }

    static class JwtPayloadWithCollectionClassRoles {
        @Subject
        long subject;
        @Roles
        Set<String> roles;

        public JwtPayloadWithCollectionClassRoles(long subject, Set<String> roles) {
            this.subject = subject;
            this.roles = roles;
        }
    }

    static class JwtPayloadWithNoneCollectionClassRoles {
        @Subject
        long subject;
        @Roles
        String roles;

        public JwtPayloadWithNoneCollectionClassRoles(long subject, String roles) {
            this.subject = subject;
            this.roles = roles;
        }
    }

    static class JwtPayloadWithOtherObjectSetRoles {
        @Subject
        long subject;
        @Roles
        Set<Object> roles;

        public JwtPayloadWithOtherObjectSetRoles(long subject, Set<Object> roles) {
            this.subject = subject;
            this.roles = roles;
        }
    }

    static class JwtPayloadWithSubjectFieldNameId {
        @Subject
        long id;
        @Roles
        Set<String> roles;

        public JwtPayloadWithSubjectFieldNameId(long id, Set<String> roles) {
            this.id = id;
            this.roles = roles;
        }
    }

    static class JwtPayloadWithRolesFieldNameAuthorities {
        @Subject
        long id;
        @Roles
        Set<String> authorities;

        public JwtPayloadWithRolesFieldNameAuthorities(long id, Set<String> authorities) {
            this.id = id;
            this.authorities = authorities;
        }
    }

    static class JwtPayloadWithNoSubject {
        @Roles
        Set<String> roles;

        public JwtPayloadWithNoSubject(Set<String> roles) {
            this.roles = roles;
        }
    }

    static class JwtPayloadWithTwoSubject {
        @Subject
        long subject1;
        @Subject
        long subject2;
        @Roles
        Set<String> roles;

        public JwtPayloadWithTwoSubject(long subject1, long subject2, Set<String> roles) {
            this.subject1 = subject1;
            this.subject2 = subject2;
            this.roles = roles;
        }
    }

    static class JwtPayloadWithNoRoles {
        @Subject
        long subject;

        public JwtPayloadWithNoRoles(long subject) {
            this.subject = subject;
        }
    }

    static class JwtPayloadWithTwoRoles {
        @Subject
        long subject;
        @Roles
        Set<String> roles1;
        @Roles
        Set<String> roles2;

        public JwtPayloadWithTwoRoles(long subject, Set<String> roles1, Set<String> roles2) {
            this.subject = subject;
            this.roles1 = roles1;
            this.roles2 = roles2;
        }
    }
}
