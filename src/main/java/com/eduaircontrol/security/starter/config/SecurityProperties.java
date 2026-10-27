package com.eduaircontrol.security.starter.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "eduair.security")
public record SecurityProperties(String jwksUri, String issuer, String audience) {
    public SecurityProperties {
        if (jwksUri == null) jwksUri = "http://localhost:8081/api/v1/auth/jwks";
    }
}
