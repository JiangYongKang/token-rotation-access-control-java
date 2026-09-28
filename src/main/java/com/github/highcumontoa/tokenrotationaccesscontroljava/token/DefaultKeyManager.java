package com.github.highcumontoa.tokenrotationaccesscontroljava.token;

import com.github.highcumontoa.tokenrotationaccesscontroljava.config.SecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * HMAC signing keys are derived deterministically from the configured master secret and a key id,
 * so no key material needs to be persisted. On rotation the previous key is discarded immediately:
 * access tokens signed with it can no longer be verified and are rejected as UNKNOWN_SIGNING_KEY.
 */
@Component
public class DefaultKeyManager implements KeyManager {

    private record KeyState(String currentKeyId, Map<String, SecretKey> keys) {
    }

    private static final Logger log = LoggerFactory.getLogger(DefaultKeyManager.class);

    private final SecurityProperties properties;
    private final AtomicReference<KeyState> state;

    public DefaultKeyManager(SecurityProperties properties) {
        this.properties = properties;
        SecretKey initial = deriveKey(properties.getMasterSecret(), properties.getInitialKeyId());
        this.state = new AtomicReference<>(new KeyState(
                properties.getInitialKeyId(),
                Map.of(properties.getInitialKeyId(), initial)));
        log.info("KeyManager initialized with current signing key id={}", properties.getInitialKeyId());
    }

    @Override
    public String currentKeyId() {
        return state.get().currentKeyId();
    }

    @Override
    public SecretKey key(String keyId) {
        return state.get().keys().get(keyId);
    }

    @Override
    public String rotate() {
        while (true) {
            KeyState current = state.get();
            String newKeyId = "k" + System.nanoTime();
            SecretKey newKey = deriveKey(properties.getMasterSecret(), newKeyId);
            KeyState next = new KeyState(newKeyId, Map.of(newKeyId, newKey));
            if (state.compareAndSet(current, next)) {
                log.info("Signing key rotated: oldKeyId={} newKeyId={}", current.currentKeyId(), newKeyId);
                return newKeyId;
            }
        }
    }

    static SecretKey deriveKey(String masterSecret, String keyId) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(masterSecret.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) ':');
            digest.update(keyId.getBytes(StandardCharsets.UTF_8));
            byte[] raw = digest.digest();
            return new SecretKeySpec(raw, "HmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    static String toHex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }
}
