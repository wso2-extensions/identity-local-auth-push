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
