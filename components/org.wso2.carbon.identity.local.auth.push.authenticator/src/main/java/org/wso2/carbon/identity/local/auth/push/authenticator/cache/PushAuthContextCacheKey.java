package org.wso2.carbon.identity.local.auth.push.authenticator.cache;

import org.wso2.carbon.identity.core.cache.CacheKey;

/**
 * Cache key for Push Authentication Context.
 */
public class PushAuthContextCacheKey extends CacheKey {

    private static final long serialVersionUID = -7140147817996455781L;
    private final String cacheKey;

    public PushAuthContextCacheKey(String cacheKeyString) {

        this.cacheKey = cacheKeyString;
    }

    public String getCacheKeyString() {

        return cacheKey;
    }

    @Override
    public boolean equals(Object o) {

        if (!(o instanceof PushAuthContextCacheKey)) {
            return false;
        }
        return this.cacheKey.equals(((PushAuthContextCacheKey) o).getCacheKeyString());
    }

    @Override
    public int hashCode() {

        return cacheKey.hashCode();
    }
}
