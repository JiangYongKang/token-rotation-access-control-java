package com.github.highcumontoa.tokenrotationaccesscontroljava.store;

import com.github.highcumontoa.tokenrotationaccesscontroljava.domain.Role;
import com.github.highcumontoa.tokenrotationaccesscontroljava.domain.User;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 用户本地存储（内存模拟），并负责按当前状态实时聚合用户有效权限：
 * 直接权限 + 各角色当前权限。访问判定每请求都调用这里，而不是读令牌快照。
 */
@Component
public class UserStore {

    private static final String DEMO_SALT = "local-demo-salt";

    private final ConcurrentHashMap<String, User> byId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> usernameToId = new ConcurrentHashMap<>();
    private final RoleStore roleStore;

    public UserStore(RoleStore roleStore) {
        this.roleStore = roleStore;
    }

    public static String hashPassword(String rawPassword) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update((DEMO_SALT + ":").getBytes(StandardCharsets.UTF_8));
            byte[] hash = digest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    public User create(String id, String username, String rawPassword) {
        User user = new User(id, username, hashPassword(rawPassword));
        byId.put(id, user);
        usernameToId.put(username, id);
        return user;
    }

    public User findById(String id) {
        return byId.get(id);
    }

    public Optional<User> findByUsername(String username) {
        String id = usernameToId.get(username);
        return id == null ? Optional.empty() : Optional.ofNullable(byId.get(id));
    }

    /**
     * 实时计算用户的有效权限集合。角色权限被修改或用户角色被调整后，
     * 这里立即反映新结果，旧令牌携带的请求也只能按新权限判定。
     */
    public Set<String> effectivePermissions(User user) {
        Set<String> permissions = new LinkedHashSet<>(user.getDirectPermissions());
        for (String roleName : user.getRoles()) {
            Role role = roleStore.find(roleName);
            if (role != null) {
                permissions.addAll(role.getPermissions());
            }
        }
        return Collections.unmodifiableSet(permissions);
    }

    public Set<String> rolesOf(User user) {
        return user.getRoles();
    }
}
