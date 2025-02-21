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

package org.wso2.carbon.identity.local.auth.push.servlet;

import org.wso2.carbon.identity.local.auth.push.servlet.cache.PushAuthStatusCacheEntry;

/**
 * Push authentication status cache manager.
 */
public interface PushAuthStatusCacheManager {

    /**
     * Store push authentication status.
     *
     * @param key           Unique key for identifying the push auth status for the session.
     * @param status         Push auth status cache.
     */
    void storeStatusCache(String key, String status);


    /**
     * Store push authentication status to the database only and invalidate the cache.
     *
     * @param key           Unique key for identifying the push auth status for the session.
     * @param status         Push auth status cache.
     */
    void storeStatusCacheToDbOnly(String key, String status);

    /**
     * Get stored authentication status.
     *
     * @param key           Unique key for identifying the push auth status for the session.
     * @return              Push Auth status cache entry.
     */
    PushAuthStatusCacheEntry getStatusCache(String key);

    /**
     * Remove the push auth status from storage to end its usage.
     *
     * @param key           Unique key for identifying the push auth status for the session.
     */
    void clearStatusCache(String key);
}
