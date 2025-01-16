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
