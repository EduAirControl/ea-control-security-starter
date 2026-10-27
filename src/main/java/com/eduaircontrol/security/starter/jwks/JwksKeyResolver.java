package com.eduaircontrol.security.starter.jwks;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.web.client.RestTemplate;

/**
 * Resuelve la clave publica RSA con la que esta firmado un access token (ADR-006).
 *
 * <p>Dos modos:
 * <ul>
 *   <li><b>Produccion</b>: {@code jwksUri} apunta al JWKS de ms-security.</li>
 *   <li><b>Tests / sin red</b>: {@code publicKeyPath} carga una clave PEM fija.</li>
 * </ul>
 */
public class JwksKeyResolver {

    private final String jwksUri;
    private final String publicKeyPath;
    private final RestTemplate restTemplate;
    private final Map<String, PublicKey> cache = new ConcurrentHashMap<>();

    public JwksKeyResolver(String jwksUri, String publicKeyPath) {
        this.jwksUri = jwksUri == null ? "" : jwksUri.trim();
        this.publicKeyPath = publicKeyPath == null ? "" : publicKeyPath.trim();
        this.restTemplate = new RestTemplate();
    }

    public Key resolve(String kid) {
        if (!publicKeyPath.isEmpty()) {
            return loadFromFile();
        }
        if (kid == null) {
            throw new IllegalArgumentException("Missing kid in JWT header");
        }
        return cache.computeIfAbsent(kid, this::fetch);
    }

    private PublicKey loadFromFile() {
        try {
            String pem = Files.readString(Path.of(publicKeyPath));
            String base64 = pem.replaceAll("-----BEGIN [A-Z ]+-----", "")
                    .replaceAll("-----END [A-Z ]+-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(base64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception ex) {
            throw new IllegalStateException("Cannot load RSA public key from " + publicKeyPath, ex);
        }
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
