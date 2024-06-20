# ❄️ Winter Security

[![Build Status](https://github.com/wwan13/winter-security/actions/workflows/ci.yml/badge.svg)](https://github.com/wwan13/winter-security/actions/workflows/ci.yml)
[![](https://jitpack.io/v/wwan13/winter-security.svg)](https://jitpack.io/#wwan13/winter-security)
[![License](https://img.shields.io/:license-apache-brightgreen.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

Custom web security library using jwt token

> If you're interested in following the project's progress, please press the ⭐ button.

<br/>

## Dependencies

```groovy
repositories {
    mavenCentral()
    maven { url 'https://jitpack.io' }
}
```

```groovy
dependencies {
    implementation 'com.github.wwan13:winter-security:0.0.2'
}
```

## How To Use

### 1. Jwt Provider

If your module includes a login API or requires issuance of jwt tokens, you should use this options.

**1.1 Configuration**

```java

@Configuration
@EnableJwtProvider
public class SecurityConfig implements JwtProviderConfigurer {

    @Override
    public void configureSecretKey(SecretKeyRegistry registry) {
        registry
                .secretKey("d2ludGVyLXNlY3VyaXR5LWV4YW1wbGUK");
    }

    @Override
    public void configureJwt(JwtPropertiesRegistry registry) {
        registry
                .accessTokenValidity(1000000L)
                .refreshTokenValidity(3000000L);
    }
}
```

This is the step to set the information required for JWT token creation.   
Enter the secretKey and expiration period for each token.

<br/>

```java

@Payload
public record TokenPayload(
        @Subject
        long id,
        @Roles
        Set<String> roles // String roles
) {
}
```

Declare the payload that makes up the JWT token as follows.  
You can create a JWT token using the payload declared here.

> If you want to use only one role, you can use a single type rather than a Collection type.

<br/>

**1.2 Using Jwt Providers**

Now you can generate and decode JWT tokens like this.

```java

@Service
public class TokenService {

    private final TokenGenerator tokenGenerator;
    private final TokenDecoder tokenDecoder;

    public TokenService(TokenGenerator tokenGenerator, TokenDecoder tokenDecoder) {
        this.tokenGenerator = tokenGenerator;
        this.tokenDecoder = tokenDecoder;
    }

    public String generateToken(long id, String role) {
        TokenPayload payload = new TokenPayload(id, role);

        String accessToken = tokenGenerator.accessToken(payload);
        String refreshToken = tokenGenerator.refreshToken(payload);

        return accessToken;
    }

    public TokenClaims decodeToken(String token) {
        TokenClaims claims = tokenDecoder.decode(token);

        long subject = (long) claims.getSubject();
        Set<String> roles = claims.getRoles();
        boolean isAccessToken = claims.isAccessToken();
        boolean isRefreshToken = claims.isRefreshToken();

        return claims;
    }
}
```

Each token can be created using TokenGenerator's `accessToken()` and `refreshToken()`.  
And the generated token can be decoded using TokenDecoder. And it contains the token's subject,
roles, and token type.

<br/>

### 2. Secure Request

If your API requests require permission management you should use this.

**2.1. Configuration**

```java

@Configuration
@EnableSecureRequest
public class SecurityConfig implements SecureRequestConfigurer {

    @Override
    public void configureSecretKey(SecretKeyRegistry registry) {
        registry
                .secretKey("d2ludGVyLXNlY3VyaXR5LWV4YW1wbGUK");
    }

    @Override
    public void registerAuthPatterns(AuthPatternsRegistry registry) {
        registry
                .uriPatterns("/api/admin/**")
                .allHttpMethods()
                .hasRoles("ROLE_ADMIN")

                .uriPatterns("/api/user/**")
                .allHttpMethods()
                .hasRoles("ROLE_USER")

                .uriPatterns("/api/token")
                .httpMethodPost()
                .permitAll()

                .elseRequestAuthenticated();
    }

    @Override
    public void registerTargetAnnotations(TargetAnnotationsRegistry registry) {
        registry
                .addSubjectResolveAnnotation(RequestUserCustomId.class);
    }
}
```

By implementing SecureRequestConfiguirer, you can set access permissions for each API request.  
Also, if you have a custom annotation that you would like to use when resolving arguments, you can
register that as well.

<br/>

**2.1. Using Secure Requests**

```java

@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/id")
    public ResponseEntity<IdResponse> getUserId(
            @RequestUserId long id
    ) {
        return ResponseEntity.ok().body(new IdResponse(id));
    }

    @GetMapping("/role")
    public ResponseEntity<RoleResponse> getUserRole(
            @RequestUserRoles Set<String> roles
    ) {
        return ResponseEntity.ok().body(new RoleResponse(role));
    }

    @GetMapping("/customId")
    public ResponseEntity<CustomIdResponse> getCustomUserId(
            @RequestUserCustomId long customId
    ) {
        return ResponseEntity.ok().body(new CustomIdResponse(customId));
    }
}
```

Now you can get the information of the user who requested the API in a similar way
using `@RequestBody` like this.

<br/>

### 3. Additional

If you want to use both functions at the same time, set them as follows.

```java

@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/id")
    public ResponseEntity<IdResponse> getUserId(
            @RequestUserId long id
    ) {
        return ResponseEntity.ok().body(new IdResponse(id));
    }

    @GetMapping("/role")
    public ResponseEntity<RoleResponse> getUserRole(
            @RequestUserRoles String role
    ) {
        return ResponseEntity.ok().body(new RoleResponse(role));
    }

    @GetMapping("/customId")
    public ResponseEntity<CustomIdResponse> getCustomUserId(
            @RequestUserCustomId long customId
    ) {
        return ResponseEntity.ok().body(new CustomIdResponse(customId));
    }
}
```

> JwtPrivider and SecureRequest both include PasswordEncoder and TokenDecoder. Therefore, there is
> no need to use unnecessary JwtPrivider functions for reasons such as refreshToken processing.

<br/>

### 4. Enjoy Your Programming

Please contact us via the [email](wwan13@naver.com) if an error occurs during use.

<br/>

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

<br/>

## License

This project is licensed under the terms of the [apache 2.0] license.

[apache 2.0]: LICENSE.txt
