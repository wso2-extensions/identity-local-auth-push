/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.push.servlet;

import com.google.gson.Gson;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.push.servlet.cache.PushAuthStatusCacheEntry;
import org.wso2.carbon.identity.local.auth.push.servlet.constant.PushServletConstants;
import org.wso2.carbon.identity.local.auth.push.servlet.impl.PushAuthStatusCacheManagerImpl;
import org.wso2.carbon.identity.local.auth.push.servlet.model.PushAuthStatus;
import org.wso2.carbon.identity.local.auth.push.servlet.model.ServletApiError;

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
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {

        if (!(request.getParameterMap().containsKey(AuthenticatorConstants.PUSH_AUTH_ID))) {

            if (log.isDebugEnabled()) {
                log.debug(PushServletConstants.ErrorMessages.ERROR_CODE_PUSH_AUTH_ID_NOT_FOUND_IN_STATUS.toString());
            }
            handleAPIErrorResponse(response,
                    PushServletConstants.ErrorMessages.ERROR_CODE_PUSH_AUTH_ID_NOT_FOUND_IN_STATUS,
                    HttpServletResponse.SC_NOT_FOUND);

        } else {
            try {
                handleWebResponse(request, response);
            } catch (IOException e) {
                log.error("Error occurred while handling the push auth status response..", e);
                handleAPIErrorResponse(response, PushServletConstants.ErrorMessages.ERROR_CODE_INTERNAL_SERVER_ERROR,
                        HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
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
                log.debug("Device authentication response has not been received yet.");
            }

        } else if (PushServletConstants.Status.COMPLETED.name().equals(authCache.getStatus())) {
            // Set the status to COMPLETED if the status is found.
            pushAuthStatus.setStatus(COMPLETED.name());
            pushAuthStatusCacheManager.clearStatusCache(pushAuthId);
        }

        String jsonResponse = new Gson().toJson(pushAuthStatus);
        response.getWriter().write(jsonResponse);
        response.getWriter().flush();
    }

    /**
     * Handle the API error response.
     *
     * @param response HTTP response
     * @param error    Error message
     * @param statusCode HTTP status code
     */
    private void handleAPIErrorResponse(HttpServletResponse response, PushServletConstants.ErrorMessages error,
                                        int statusCode) {

        try {
            response.setStatus(statusCode);
            ServletApiError servletApiError = new ServletApiError(error.getCode(), error.getMessage());
            String jsonResponse = new Gson().toJson(servletApiError);
            response.getWriter().write(jsonResponse);
            response.getWriter().flush();
        } catch (IOException e) {
            log.error("Error occurred while sending the error response.", e);
        }
    }
}
