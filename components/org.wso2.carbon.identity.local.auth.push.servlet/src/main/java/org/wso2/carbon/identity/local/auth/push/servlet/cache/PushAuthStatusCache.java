package org.wso2.carbon.identity.local.auth.push.servlet.cache;

import org.wso2.carbon.identity.core.cache.BaseCache;

/**
 * This cache is implemented to track the status of the ongoing push authentication requests.
 */
public class PushAuthStatusCache extends BaseCache<PushAuthStatusCacheKey, PushAuthStatusCacheEntry> {

    private static final String PUSH_AUTH_STATUS_CACHE = "PushAuthStatusCache";
    private static final PushAuthStatusCache INSTANCE = new PushAuthStatusCache();

    private PushAuthStatusCache() {
        super(PUSH_AUTH_STATUS_CACHE, true);
    }

    public static PushAuthStatusCache getInstance() {
        return INSTANCE;
    }
}
