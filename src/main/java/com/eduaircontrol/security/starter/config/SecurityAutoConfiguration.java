package com.eduaircontrol.security.starter.config;

import com.eduaircontrol.security.starter.filter.JwtAuthFilter;
import com.eduaircontrol.security.starter.jwks.JwksKeyResolver;
import com.eduaircontrol.security.starter.jwt.JwtService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@EnableConfigurationProperties(SecurityProperties.class)
public class SecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwksKeyResolver jwksKeyResolver(SecurityProperties properties) {
        return new JwksKeyResolver(properties.jwksUri());
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
