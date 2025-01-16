package org.wso2.carbon.identity.local.auth.push.authenticator.cache;

import org.wso2.carbon.identity.core.cache.CacheEntry;
import org.wso2.carbon.identity.local.auth.push.authenticator.model.PushAuthContext;

/**
 * Cache entry for Push Authentication Context.
 */
public class PushAuthContextCacheEntry extends CacheEntry {

    private static final long serialVersionUID = -7483300443936061157L;
    private final PushAuthContext pushAuthContext;

    public PushAuthContextCacheEntry(PushAuthContext pushAuthContext) {

        this.pushAuthContext = pushAuthContext;
    }

    public PushAuthContext getPushAuthContext() {

        return pushAuthContext;
    }

}
