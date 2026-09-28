package com.github.highcumontoa.tokenrotationaccesscontroljava.token;

import com.github.highcumontoa.tokenrotationaccesscontroljava.model.DenyReason;

public sealed interface ParseResult {

    record Valid(Claims claims) implements ParseResult {
    }

    record Invalid(DenyReason reason, String detail, String tokenId) implements ParseResult {
    }
}
