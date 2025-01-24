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

package org.wso2.carbon.identity.local.auth.push.servlet.cache;

import org.wso2.carbon.identity.core.cache.CacheKey;

/**
 * Cache key for Push Authentication Status.
 */
public class PushAuthStatusCacheKey extends CacheKey {

    private static final long serialVersionUID = 5208578431308376601L;
    private final String cacheKey;

    public PushAuthStatusCacheKey(String cacheKeyString) {

        this.cacheKey = cacheKeyString;
    }

    public String getCacheKeyString() {

        return cacheKey;
    }

    @Override
    public boolean equals(Object o) {

        if (!(o instanceof PushAuthStatusCacheKey)) {
            return false;
        }
        return this.cacheKey.equals(((PushAuthStatusCacheKey) o).getCacheKeyString());
    }

    @Override
    public int hashCode() {

        return cacheKey.hashCode();
    }
}
