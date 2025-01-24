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

package org.wso2.carbon.identity.local.auth.push.authenticator.cache;

import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationBaseCache;
import org.wso2.carbon.utils.CarbonUtils;

import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTH_CONTEXT_CACHE;

/**
 * Cache entry for Push Authentication Context.
 */
public class PushAuthContextCache extends AuthenticationBaseCache<PushAuthContextCacheKey, PushAuthContextCacheEntry> {

    private static volatile PushAuthContextCache instance;

    private PushAuthContextCache() {

        super(PUSH_AUTH_CONTEXT_CACHE, true);
    }

    /**
     * Get Push auth context cache by type instance.
     *
     * @return Push auth context cache by type instance.
     */
    public static PushAuthContextCache getInstance() {

        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (PushAuthContextCache.class) {
                if (instance == null) {
                    instance = new PushAuthContextCache();
                }
            }
        }
        return instance;
    }

}
