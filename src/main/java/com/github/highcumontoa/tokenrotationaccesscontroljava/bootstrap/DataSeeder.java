package com.github.highcumontoa.tokenrotationaccesscontroljava.bootstrap;

import com.github.highcumontoa.tokenrotationaccesscontroljava.auth.PasswordHasher;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.Role;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.UserAccount;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.UserStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Seeds local demo accounts. Passwords are stored hashed; nothing here is a real credential.
 *
 * <pre>
 * viewer / viewer-pass  -> DOCS_READ
 * editor / editor-pass  -> DOCS_READ, DOCS_WRITE
 * admin  / admin-pass   -> all permissions
 * </pre>
 */
@Component
public class DataSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataSeeder.class);

    private final UserStore userStore;
    private final PasswordHasher passwordHasher;

    public DataSeeder(UserStore userStore, PasswordHasher passwordHasher) {
        this.userStore = userStore;
        this.passwordHasher = passwordHasher;
    }

    @Override
    public void run(String... args) {
        seed("viewer", "viewer-pass", List.of(Role.VIEWER));
        seed("editor", "editor-pass", List.of(Role.EDITOR));
        seed("admin", "admin-pass", List.of(Role.ADMIN));
        log.info("Demo accounts seeded: viewer/viewer-pass, editor/editor-pass, admin/admin-pass");
    }

    private void seed(String username, String rawPassword, List<Role> roles) {
        if (userStore.findByUsername(username).isEmpty()) {
            userStore.save(new UserAccount(username, passwordHasher.hash(rawPassword),
                    roles, 1, true));
        }
    }
}
