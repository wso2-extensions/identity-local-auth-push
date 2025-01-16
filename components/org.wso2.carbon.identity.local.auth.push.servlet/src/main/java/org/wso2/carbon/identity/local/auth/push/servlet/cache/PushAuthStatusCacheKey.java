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
