package org.wso2.carbon.identity.local.auth.push.servlet.impl;

import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.local.auth.push.servlet.PushAuthStatusCacheManager;
import org.wso2.carbon.identity.local.auth.push.servlet.cache.PushAuthStatusCache;
import org.wso2.carbon.identity.local.auth.push.servlet.cache.PushAuthStatusCacheEntry;
import org.wso2.carbon.identity.local.auth.push.servlet.cache.PushAuthStatusCacheKey;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils.getLoginTenantDomainFromContext;

/**
 * Implementation of the PushAuthStatusCacheManager.
 */
public class PushAuthStatusCacheManagerImpl implements PushAuthStatusCacheManager {

    public static final String PUSH_AUTH_STATUS_CACHE = "PushAuthStatusCache";

    @Override
    public void storeStatusCache(String key, String status) {

        PushAuthStatusCacheEntry pushAuthStatusCacheEntry = new PushAuthStatusCacheEntry(status);
        PushAuthStatusCache.getInstance().addToCache(new PushAuthStatusCacheKey(key), pushAuthStatusCacheEntry,
                getLoginTenantDomainFromContext());
        storeToSessionStore(key, pushAuthStatusCacheEntry);
    }

    @Override
    public PushAuthStatusCacheEntry getStatusCache(String key) {

        PushAuthStatusCacheEntry pushAuthStatusCacheEntry = PushAuthStatusCache.getInstance().getValueFromCache(
                new PushAuthStatusCacheKey(key), getLoginTenantDomainFromContext());
        if (pushAuthStatusCacheEntry != null) {
            return pushAuthStatusCacheEntry;
        } else {
            return getFromSessionStore(key);
        }
    }

    @Override
    public void clearStatusCache(String key) {

        PushAuthStatusCache.getInstance().clearCacheEntry(
                new PushAuthStatusCacheKey(key), getLoginTenantDomainFromContext());
        clearFromSessionStore(key);
        // session
    }

    /**
     * Store push authentication status in session store.
     *
     * @param id            Unique key for identifying the push auth status for the session.
     * @param entry         Push auth status cache entry.
     */
    private void storeToSessionStore(String id, PushAuthStatusCacheEntry entry) {

        SessionDataStore.getInstance().storeSessionData(id, PUSH_AUTH_STATUS_CACHE, entry);
    }

    /**
     * Get push authentication status from session store.
     *
     * @param key           Unique key for identifying the push auth status for the session.
     * @return              Push Auth status stored under unique key.
     */
    private PushAuthStatusCacheEntry getFromSessionStore(String key) {

        return (PushAuthStatusCacheEntry) SessionDataStore.getInstance().getSessionData(key, PUSH_AUTH_STATUS_CACHE);
    }

    /**
     * Remove the push auth status from storage to end its usage.
     *
     * @param key           Unique key for identifying the push auth status for the session.
     */
    private void clearFromSessionStore(String key) {

        SessionDataStore.getInstance().clearSessionData(key, PUSH_AUTH_STATUS_CACHE);
    }

}
