package com.github.highcumontoa.tokenrotationaccesscontroljava.store;

import com.github.highcumontoa.tokenrotationaccesscontroljava.domain.Role;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 角色本地存储（内存模拟）。角色权限可变，变更对后续所有访问判定立即生效。
 */
@Component
public class RoleStore {

    private final ConcurrentHashMap<String, Role> roles = new ConcurrentHashMap<>();

    public Role createIfAbsent(String name) {
        return roles.computeIfAbsent(name, Role::new);
    }

    public Role find(String name) {
        return roles.get(name);
    }

    public Collection<Role> all() {
        return Collections.unmodifiableCollection(roles.values());
    }

    /** 修改角色权限；返回是否修改成功（角色不存在返回 false）。 */
    public boolean addPermission(String roleName, String permission) {
        Role role = roles.get(roleName);
        if (role == null) {
            return false;
        }
        role.addPermission(permission);
        return true;
    }

    public boolean removePermission(String roleName, String permission) {
        Role role = roles.get(roleName);
        if (role == null) {
            return false;
        }
        role.removePermission(permission);
        return true;
    }
}
