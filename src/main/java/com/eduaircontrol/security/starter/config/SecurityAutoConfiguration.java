package com.eduaircontrol.security.starter.config;

import com.eduaircontrol.security.starter.filter.JwtAuthFilter;
import com.eduaircontrol.security.starter.jwks.JwksKeyResolver;
import com.eduaircontrol.security.starter.jwt.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class SecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwksKeyResolver jwksKeyResolver(
            @Value("${security.jwks-uri:}") String jwksUri,
            @Value("${security.rsa.public-key-path:}") String publicKeyPath) {
        return new JwksKeyResolver(jwksUri, publicKeyPath);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtService jwtService(JwksKeyResolver resolver) {
        return new JwtService(resolver);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthFilter jwtAuthFilter(JwtService jwtService) {
        return new JwtAuthFilter(jwtService);
    }
}
