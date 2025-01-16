package org.wso2.carbon.identity.local.auth.push.servlet.cache;

import org.wso2.carbon.identity.core.cache.CacheEntry;

/**
 * Cache entry for Push Authentication Status.
 */
public class PushAuthStatusCacheEntry extends CacheEntry {

    private static final long serialVersionUID = 7042710411856025020L;
    private final String status;

    public PushAuthStatusCacheEntry(String status) {
        this.status = status;
    }

    public String getStatus() {
        return status;
    }
}
