package org.wso2.carbon.identity.local.auth.push.authenticator.exception;

/**
 * Exception class for Push Authenticator Server.
 */
public class PushAuthenticatorServerException extends PushAuthenticatorException {

    private static final long serialVersionUID = -8023325829039787468L;

    /**
     * Constructs a new exception with an error code, detail message and throwable.
     *
     * @param errorCode The error code.
     * @param message   The detail message.
     * @param throwable Throwable.
     */
    public PushAuthenticatorServerException(String errorCode, String message, Throwable throwable) {

        super(errorCode, message, throwable);
        this.setErrorCode(errorCode);
    }
}
