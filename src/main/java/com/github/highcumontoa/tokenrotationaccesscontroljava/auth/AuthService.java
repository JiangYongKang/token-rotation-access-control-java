package com.github.highcumontoa.tokenrotationaccesscontroljava.auth;

import com.github.highcumontoa.tokenrotationaccesscontroljava.model.IssuedTokens;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.RefreshConsumeOutcome;

import java.util.List;

public interface AuthService {

    sealed interface LoginResult {
        record Success(IssuedTokens tokens) implements LoginResult {
        }
        record Failure(String reason, String detail) implements LoginResult {
        }
    }

    LoginResult login(String username, String password);

    RefreshConsumeOutcome refresh(String refreshToken);

    boolean logout(String refreshToken, String reason);

    int logoutUser(String username, String reason);

    int rotateUserCredential(String username, String newRawPassword);

    int rotateUserRoles(String username, List<String> roles);
}
