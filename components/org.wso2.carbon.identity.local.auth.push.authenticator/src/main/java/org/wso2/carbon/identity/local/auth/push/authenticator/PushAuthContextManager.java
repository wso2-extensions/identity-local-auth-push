package org.wso2.carbon.identity.local.auth.push.authenticator;

import org.wso2.carbon.identity.local.auth.push.authenticator.model.PushAuthContext;

/**
 * This interface manages push auth context operations for push based authentication.
 */
public interface PushAuthContextManager {

    /**
     * Store push authentication context.
     *
     * @param key           Unique key for identifying the push auth context for the session.
     * @param context       Push auth context.
     */
    void storeContext(String key, PushAuthContext context);

    /**
     * Get stored authentication context.
     *
     * @param key           Unique key for identifying the push auth context for the session.
     * @return              Push Auth context stored under unique key.
     */
    PushAuthContext getContext(String key);

    /**
     * Remove the push auth context from storage to end its usage.
     *
     * @param key           Unique key for identifying the push auth context for the session.
     */
    void clearContext(String key);
}
