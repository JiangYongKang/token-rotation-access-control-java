package com.github.highcumontoa.tokenrotationaccesscontroljava.domain;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 本地用户：密码以哈希形式保存（演示用 SHA-256），角色可变，可被禁用。
 * 用户被禁用或角色/权限被修改后，下一次携带旧令牌访问时就会按最新状态判定。
 */
public class User {

    private final String id;
    private final String username;
    private final String passwordHash;
    private final Set<String> roles = new LinkedHashSet<>();
    private final Set<String> directPermissions = new LinkedHashSet<>();
    private volatile boolean enabled = true;

    public User(String id, String username, String passwordHash) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
    }

    public String getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public synchronized Set<String> getRoles() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(roles));
    }

    public synchronized void addRole(String roleName) {
        roles.add(roleName);
    }

    public synchronized Set<String> getDirectPermissions() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(directPermissions));
    }

    public synchronized void addDirectPermission(String permission) {
        directPermissions.add(permission);
    }

    public synchronized void removeDirectPermission(String permission) {
        directPermissions.remove(permission);
    }
}
