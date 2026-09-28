package com.github.highcumontoa.tokenrotationaccesscontroljava.web.dto;

import java.util.List;

public record ChangeRolesRequest(String username, List<String> roles) {
}
