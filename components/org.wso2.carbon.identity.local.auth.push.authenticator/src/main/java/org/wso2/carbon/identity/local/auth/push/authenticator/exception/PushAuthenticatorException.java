package org.wso2.carbon.identity.local.auth.push.authenticator.exception;

import org.wso2.carbon.identity.base.IdentityException;

/**
 * Push Authenticator Exception.
 */
public class PushAuthenticatorException extends IdentityException {

    private static final long serialVersionUID = -5257809255454125379L;

    /**
     * Constructs a new exception with an error code, detail message and throwable.
     *
     * @param errorCode The error code.
     * @param message   The detail message.
     * @param throwable Throwable.
     */
    public PushAuthenticatorException(String errorCode, String message, Throwable throwable) {

        super(errorCode, message, throwable);
        this.setErrorCode(errorCode);
    }
}
