package com.eduaircontrol.security.starter.jwks;

import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.web.client.RestTemplate;

/**
 * Resuelve la clave pública RSA a partir del JWKS publicado por ms-security.
 * Cachea las claves por kid para evitar peticiones repetidas.
 */
public class JwksKeyResolver {

    private final String jwksUri;
    private final RestTemplate restTemplate;
    private final Map<String, PublicKey> cache = new ConcurrentHashMap<>();

    public JwksKeyResolver(String jwksUri) {
        this.jwksUri = jwksUri;
        this.restTemplate = new RestTemplate();
    }

    public Key resolve(String kid) {
        if (kid == null) {
            throw new IllegalArgumentException("Missing kid in JWT header");
        }
        return cache.computeIfAbsent(kid, this::fetch);
    }

    @SuppressWarnings("unchecked")
    private PublicKey fetch(String kid) {
        Map<String, Object> jwks = restTemplate.getForObject(jwksUri, Map.class);
        if (jwks == null || !(jwks.get("keys") instanceof java.util.List<?> keys)) {
            throw new IllegalStateException("Invalid JWKS response");
        }
        for (Object o : keys) {
            if (!(o instanceof Map<?, ?> entry)) continue;
            if (!kid.equals(entry.get("kid"))) continue;
            String n = (String) entry.get("n");
            String e = (String) entry.get("e");
            if (n == null || e == null) continue;
            try {
                java.math.BigInteger modulus = new java.math.BigInteger(1, java.util.Base64.getUrlDecoder().decode(n));
                java.math.BigInteger exponent = new java.math.BigInteger(1, java.util.Base64.getUrlDecoder().decode(e));
                java.security.spec.RSAPublicKeySpec spec = new java.security.spec.RSAPublicKeySpec(modulus, exponent);
                java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
                return kf.generatePublic(spec);
            } catch (Exception ex) {
                throw new IllegalStateException("Cannot build RSA key for kid " + kid, ex);
            }
        }
        throw new IllegalStateException("kid not found in JWKS: " + kid);
    }
}
