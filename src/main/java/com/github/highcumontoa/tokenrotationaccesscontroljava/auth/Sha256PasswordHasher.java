package com.github.highcumontoa.tokenrotationaccesscontroljava.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Local-simulation password hashing: a fixed salt plus SHA-256. This is intentionally simple for a
 * self-contained demo and must not be used as a real-world password storage scheme (use bcrypt,
 * argon2 or similar with per-user salts there).
 */
@Component
public class Sha256PasswordHasher implements PasswordHasher {

    private final String salt;

    public Sha256PasswordHasher(@Value("${app.security.password-salt:local-static-salt}") String salt) {
        this.salt = salt;
    }

    @Override
    public String hash(String rawPassword) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(salt.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) ':');
            digest.update(rawPassword.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    @Override
    public boolean matches(String rawPassword, String storedHash) {
        return MessageDigest.isEqual(
                hash(rawPassword).getBytes(StandardCharsets.UTF_8),
                storedHash.getBytes(StandardCharsets.UTF_8));
    }
}
