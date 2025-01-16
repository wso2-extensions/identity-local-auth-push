package org.wso2.carbon.identity.local.auth.push.servlet;

import com.google.gson.Gson;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.push.servlet.cache.PushAuthStatusCacheEntry;
import org.wso2.carbon.identity.local.auth.push.servlet.constant.PushServletConstants;
import org.wso2.carbon.identity.local.auth.push.servlet.impl.PushAuthStatusCacheManagerImpl;
import org.wso2.carbon.identity.local.auth.push.servlet.model.PushAuthStatus;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.local.auth.push.servlet.constant.PushServletConstants.MEDIA_TYPE_JSON;
import static org.wso2.carbon.identity.local.auth.push.servlet.constant.PushServletConstants.Status.COMPLETED;
import static org.wso2.carbon.identity.local.auth.push.servlet.constant.PushServletConstants.Status.PENDING;

/**
 * Servlet for handling the status checks for authentication requests from the push authenticator wait page.
 */
public class PushStatusServlet extends HttpServlet {

    private static final long serialVersionUID = -8827871176057704783L;
    private static final Log log = LogFactory.getLog(PushStatusServlet.class);
    private static final PushAuthStatusCacheManager pushAuthStatusCacheManager = new PushAuthStatusCacheManagerImpl();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

        if (!(request.getParameterMap().containsKey(AuthenticatorConstants.PUSH_AUTH_ID))) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);

            if (log.isDebugEnabled()) {
                log.debug(PushServletConstants.ErrorMessages.ERROR_CODE_PUSH_AUTH_ID_NOT_FOUND_IN_STATUS.toString());
            }

        } else {
            handleWebResponse(request, response);
        }
    }

    /**
     * Handles requests received from the wait page to check the authentication status.
     *
     * @param request  HTTP request
     * @param response HTTP response
     */
    private void handleWebResponse(HttpServletRequest request, HttpServletResponse response) throws IOException {

        PushAuthStatus pushAuthStatus = new PushAuthStatus();
        // Set the status to PENDING if the status is not found.
        pushAuthStatus.setStatus(PENDING.name());

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MEDIA_TYPE_JSON);

        String pushAuthId = request.getParameter(AuthenticatorConstants.PUSH_AUTH_ID);
        PushAuthStatusCacheEntry authCache = pushAuthStatusCacheManager.getStatusCache(pushAuthId);

        if (authCache == null) {
            pushAuthStatusCacheManager.storeStatusCache(pushAuthId, PENDING.name());
            if (log.isDebugEnabled()) {
                log.debug("Mobile authentication response has not been received yet.");
            }

        } else if (PushServletConstants.Status.COMPLETED.name().equals(authCache.getStatus())) {
            // Set the status to COMPLETED if the status is found.
            pushAuthStatus.setStatus(COMPLETED.name());
            pushAuthStatusCacheManager.clearStatusCache(pushAuthId);
        }

        String jsonResponse = new Gson().toJson(pushAuthStatus);
        response.getWriter().write(jsonResponse);
    }
}
