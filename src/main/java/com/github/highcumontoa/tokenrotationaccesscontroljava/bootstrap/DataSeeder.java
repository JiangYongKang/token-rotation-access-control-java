package com.github.highcumontoa.tokenrotationaccesscontroljava.bootstrap;

import com.github.highcumontoa.tokenrotationaccesscontroljava.domain.User;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.RoleStore;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.UserStore;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/**
 * 初始化本地演示数据（全部为虚构账号，密码仅存在内存中的哈希）：
 * <ul>
 *   <li>admin / admin123：admin:manage + 文章读写；</li>
 *   <li>alice / alice123：editor 角色，文章读写；</li>
 *   <li>bob / bob123：reader 角色，仅文章只读；</li>
 *   <li>carol / carol123：reader 角色，但账号初始被禁用。</li>
 * </ul>
 */
@Component
public class DataSeeder implements CommandLineRunner {

    private final UserStore userStore;
    private final RoleStore roleStore;

    public DataSeeder(UserStore userStore, RoleStore roleStore) {
        this.userStore = userStore;
        this.roleStore = roleStore;
    }

    @Override
    public void run(String... args) {
        roleStore.createIfAbsent("admin")
                .addPermission("article:read");
        roleStore.find("admin").addPermission("article:write");
        roleStore.find("admin").addPermission("admin:manage");

        roleStore.createIfAbsent("editor").addPermission("article:read");
        roleStore.find("editor").addPermission("article:write");

        roleStore.createIfAbsent("reader").addPermission("article:read");

        User admin = userStore.create("u-admin", "admin", "admin123");
        admin.addRole("admin");

        User alice = userStore.create("u-alice", "alice", "alice123");
        alice.addRole("editor");

        User bob = userStore.create("u-bob", "bob", "bob123");
        bob.addRole("reader");

        User carol = userStore.create("u-carol", "carol", "carol123");
        carol.addRole("reader");
        carol.setEnabled(false);
    }
}
