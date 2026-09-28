package com.github.highcumontoa.tokenrotationaccesscontroljava.model;

import java.util.Set;

public enum Role {
    VIEWER(Set.of(Permission.DOCS_READ)),
    EDITOR(Set.of(Permission.DOCS_READ, Permission.DOCS_WRITE)),
    ADMIN(Set.of(Permission.DOCS_READ, Permission.DOCS_WRITE,
            Permission.ADMIN_AUDIT, Permission.ADMIN_KEYS, Permission.ADMIN_USERS));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<Permission> permissions() {
        return permissions;
    }
}
