package com.github.highcumontoa.tokenrotationaccesscontroljava.token;

import javax.crypto.SecretKey;

public interface KeyManager {

    String currentKeyId();

    SecretKey key(String keyId);

    String rotate();
}
