/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

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
