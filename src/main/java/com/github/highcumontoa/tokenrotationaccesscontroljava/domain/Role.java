package com.github.highcumontoa.tokenrotationaccesscontroljava.domain;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 角色：聚合一组权限标识（如 {@code article:write}）。
 * 角色实例在本地存储中可变，权限的增删会立即影响后续访问判定，
 * 因为判定时按 userId 实时读取角色，而不是信任旧令牌中的快照。
 */
public class Role {

    private final String name;
    private final Set<String> permissions = new LinkedHashSet<>();

    public Role(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public Set<String> getPermissions() {
        return Collections.unmodifiableSet(permissions);
    }

    public void addPermission(String permission) {
        permissions.add(permission);
    }

    public void removePermission(String permission) {
        permissions.remove(permission);
    }
}
