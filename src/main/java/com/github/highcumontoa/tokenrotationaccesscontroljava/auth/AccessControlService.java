package com.github.highcumontoa.tokenrotationaccesscontroljava.auth;

import com.github.highcumontoa.tokenrotationaccesscontroljava.model.AuthDecision;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.Permission;

public interface AccessControlService {

    AuthDecision evaluate(String authorizationHeader, Permission required);
}
