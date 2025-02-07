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

package org.wso2.carbon.identity.local.auth.push.servlet.model;

/**
 * This class represents the API error responses of the push authentication servlets.
 */
public class ServletApiError {

    private String code;
    private String message;

    /**
     * Constructor for the ServletApiError class.
     *
     * @param code    Error code.
     * @param message Error message.
     */
    public ServletApiError(String code, String message) {
        this.code = code;
        this.message = message;
    }

    /**
     * Get the error code.
     *
     * @return Error code.
     */
    public String getCode() {
        return code;
    }

    /**
     * Get the error message.
     *
     * @return Error message.
     */
    public String getMessage() {
        return message;
    }

}
