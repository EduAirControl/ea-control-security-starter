# ea-control-security-starter

Shared security starter for EduAirControl microservices (G-12).

Provides:
- `JwksKeyResolver` — resolves RSA public keys from the ms-security JWKS.
- `JwtService` — validates RS256 access tokens and extracts `AuthenticatedUser`.
- `JwtAuthFilter` — servlet filter that authenticates via JWT and publishes tenant attributes.
- `TenantContext` — thread-local tenant (institutionId/campusId).
- `SecurityAutoConfiguration` — auto-configures the beans above from `eduair.security.*` properties.

## Usage

Add the dependency (GitHub Packages):

```xml
<dependency>
    <groupId>com.eduaircontrol</groupId>
    <artifactId>ea-control-security-starter</artifactId>
    <version>0.1.0</version>
</dependency>
```

Configure in `application.properties` / `application.yml`:

```yaml
eduair:
  security:
    jwks-uri: ${AUTH_JWKS_URI:http://localhost:8081/api/v1/auth/jwks}
```

Inject `JwtAuthFilter` in your `SecurityConfig`:

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthFilter jwtAuthFilter) throws Exception {
    return http
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
        .build();
}
```

## Migration (G-12.4 / G-12.5)

1. Add the dependency above.
2. Remove the local copies of `shared/security/{JwtAuthFilter,JwtService,JwksKeyResolver}` and `application/TenantContext`.
3. Update imports to `com.eduaircontrol.security.starter.*`.
4. Keep the service-specific `SecurityConfig` (path rules differ per service) but inject `JwtAuthFilter` from the starter.
5. Delete the local `shared/security/` package once no references remain.

Services still to migrate: ms-classroom-management, ms-sensor-management, ms-environment-monitoring, ms-user-experience (P1).
Already using the starter: (none yet — proof of concept pending).
