package com.github.highcumontoa.tokenrotationaccesscontroljava.model;

import java.util.List;

public record UserAccount(
        String username,
        String passwordHash,
        List<Role> roles,
        long version,
        boolean enabled) {

    public UserAccount withRoles(List<Role> newRoles) {
        return new UserAccount(username, passwordHash, newRoles, version + 1, enabled);
    }

    public UserAccount withEnabled(boolean newEnabled) {
        return new UserAccount(username, passwordHash, roles, version + 1, newEnabled);
    }

    public UserAccount withPasswordHash(String newPasswordHash) {
        return new UserAccount(username, newPasswordHash, roles, version, enabled);
    }

    public UserAccount withVersionBump() {
        return new UserAccount(username, passwordHash, roles, version + 1, enabled);
    }
}
