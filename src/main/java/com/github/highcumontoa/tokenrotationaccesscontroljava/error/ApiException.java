package com.github.highcumontoa.tokenrotationaccesscontroljava.error;

/**
 * 业务异常：携带明确的 {@link AuthzReason} 以及本次判定涉及的凭证标识，
 * 便于审计记录与 HTTP 响应给出可解释的拒绝原因。
 */
public class ApiException extends RuntimeException {

    private final AuthzReason reason;
    private final String credentialId;

    public ApiException(AuthzReason reason) {
        this(reason, reason.getDescription(), null);
    }

    public ApiException(AuthzReason reason, String credentialId) {
        this(reason, reason.getDescription(), credentialId);
    }

    public ApiException(AuthzReason reason, String message, String credentialId) {
        super(message);
        this.reason = reason;
        this.credentialId = credentialId;
    }

    public AuthzReason getReason() {
        return reason;
    }

    public String getCredentialId() {
        return credentialId;
    }
}
