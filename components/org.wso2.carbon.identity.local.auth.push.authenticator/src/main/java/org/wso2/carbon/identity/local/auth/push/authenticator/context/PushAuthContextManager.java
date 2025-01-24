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

package org.wso2.carbon.identity.local.auth.push.authenticator.context;

import org.wso2.carbon.identity.local.auth.push.authenticator.model.PushAuthContext;

/**
 * This interface manages push auth context operations for push based authentication.
 * These contexts are stored in the temp session store.
 */
public interface PushAuthContextManager {

    /**
     * Store push authentication context.
     *
     * @param key           Unique key for identifying the push auth context for the session.
     * @param context       Push auth context.
     */
    void storeContext(String key, PushAuthContext context);

    /**
     * Get stored authentication context.
     *
     * @param key           Unique key for identifying the push auth context for the session.
     * @return              Push Auth context stored under unique key.
     */
    PushAuthContext getContext(String key);

    /**
     * Remove the push auth context from storage to end its usage.
     *
     * @param key           Unique key for identifying the push auth context for the session.
     */
    void clearContext(String key);
}
