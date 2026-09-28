package com.github.highcumontoa.tokenrotationaccesscontroljava.store;

import com.github.highcumontoa.tokenrotationaccesscontroljava.model.UserAccount;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemoryUserStore implements UserStore {

    private final ConcurrentHashMap<String, UserAccount> users = new ConcurrentHashMap<>();

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        return Optional.ofNullable(users.get(username));
    }

    @Override
    public UserAccount save(UserAccount account) {
        users.put(account.username(), account);
        return account;
    }

    @Override
    public List<UserAccount> findAll() {
        return List.copyOf(users.values());
    }
}
