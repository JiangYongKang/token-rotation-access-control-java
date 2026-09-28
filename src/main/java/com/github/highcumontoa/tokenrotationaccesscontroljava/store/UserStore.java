package com.github.highcumontoa.tokenrotationaccesscontroljava.store;

import com.github.highcumontoa.tokenrotationaccesscontroljava.model.UserAccount;

import java.util.List;
import java.util.Optional;

public interface UserStore {

    Optional<UserAccount> findByUsername(String username);

    UserAccount save(UserAccount account);

    List<UserAccount> findAll();
}
