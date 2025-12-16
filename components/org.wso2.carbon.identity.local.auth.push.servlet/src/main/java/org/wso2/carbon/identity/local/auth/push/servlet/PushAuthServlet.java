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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.local.auth.push.authenticator.context.PushAuthContextManager;
import org.wso2.carbon.identity.local.auth.push.authenticator.model.PushAuthContext;
import org.wso2.carbon.identity.local.auth.push.servlet.constant.PushServletConstants;
import org.wso2.carbon.identity.local.auth.push.servlet.impl.PushAuthStatusCacheManagerImpl;
import org.wso2.carbon.identity.local.auth.push.servlet.internal.PushServletDataHolder;
import org.wso2.carbon.identity.local.auth.push.servlet.model.ServletApiError;
import org.wso2.carbon.identity.notification.push.common.PushChallengeValidator;
import org.wso2.carbon.identity.notification.push.common.exception.PushTokenValidationException;
import org.wso2.carbon.identity.notification.push.device.handler.exception.PushDeviceHandlerException;

import java.io.BufferedReader;
import java.io.IOException;
import java.text.ParseException;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.local.auth.push.servlet.constant.PushServletConstants.AUTH_RESPONSE;
import static org.wso2.carbon.identity.local.auth.push.servlet.constant.PushServletConstants.PUSH_AUTHENTICATE_SERVLET_URL;

/**
 * Servlet for handling authentication requests sent from device.
 */
//TODO Check if this servlet is working.
@Component(
        service = Servlet.class,
        immediate = true,
        property = {
                "osgi.http.whiteboard.servlet.pattern=" + PUSH_AUTHENTICATE_SERVLET_URL,
                "osgi.http.whiteboard.servlet.name=PushAuthServlet",
                "osgi.http.whiteboard.servlet.asyncSupported=true"
        }
)
public class PushAuthServlet extends HttpServlet {

    private static final long serialVersionUID = 3471640151205811758L;
    private static final Log log = LogFactory.getLog(PushAuthServlet.class);
    private static final PushAuthStatusCacheManager pushAuthStatusCacheManager = new PushAuthStatusCacheManagerImpl();

    /**
     * Handle the POST request sent from the  device.
     * Expected Payload:
     * {
     * "authResponse": "JWT Token for push auth"
     * }
     *
     * @param request  HTTP request
     * @param response HTTP response
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {

        try {
            handleDeviceResponse(request, response);
        } catch (IOException e) {
            PushServletConstants.ErrorMessages error =
                    PushServletConstants.ErrorMessages.ERROR_CODE_INTERNAL_SERVER_ERROR;
            log.error(error.getDescription(), e);
            handleAPIErrorResponse(response, error, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Handle the authentication response sent from the device.
     *
     * @param request  HTTP request
     * @param response HTTP response
     * @throws IOException      if an I/O error occurs when handling the request.
     */
    private void handleDeviceResponse(HttpServletRequest request, HttpServletResponse response) throws IOException {

        JSONObject jsonContent = readJsonContentInRequest(request, response);
        if (jsonContent == null) {
            return;
        }

        String token = jsonContent.getString(AUTH_RESPONSE);
        if (StringUtils.isBlank(token)) {

            PushServletConstants.ErrorMessages error =
                    PushServletConstants.ErrorMessages.ERROR_CODE_AUTH_RESPONSE_TOKEN_NOT_FOUND;
            if (log.isDebugEnabled()) {
                log.debug(error.getDescription());
            }
            handleAPIErrorResponse(response, error, HttpServletResponse.SC_BAD_REQUEST);

        } else {

            String deviceId = getDeviceIdFromToken(token, response);
            if (StringUtils.isBlank(deviceId)) {
                return;
            }

            JWTClaimsSet claimsSet = getClaimsSetFromAuthToken(token, deviceId, response);
            if (claimsSet == null) {
                return;
            }

            String pushAuthId;
            try {
                pushAuthId = claimsSet.getStringClaim(PushServletConstants.TOKEN_PUSH_AUTH_ID);
            } catch (ParseException e) {
                PushServletConstants.ErrorMessages error =
                        PushServletConstants.ErrorMessages.ERROR_CODE_PARSE_JWT_FAILED;
                if (log.isDebugEnabled()) {
                    log.debug(error.getDescription(), e);
                }
                handleAPIErrorResponse(response, error, HttpServletResponse.SC_BAD_REQUEST);
                return;
            }

            if (StringUtils.isBlank(pushAuthId)) {

                PushServletConstants.ErrorMessages error =
                        PushServletConstants.ErrorMessages.ERROR_CODE_PUSH_AUTH_ID_NOT_FOUND;
                if (log.isDebugEnabled()) {
                    log.debug(String.format(error.getDescription(), deviceId));
                }
                handleAPIErrorResponse(response, error, HttpServletResponse.SC_BAD_REQUEST);
            } else {

                boolean isSuccessful = addToContext(pushAuthId, token, response);
                if (!isSuccessful) {
                    return;
                }

                /*
                 * We need to invalidate the existing cache across the cluster and store the new status. But if there
                 * is a poll request in between, the cache will be created again with the old status. To avoid this,
                 * we store the new status in the database only and invalidate the cache. So, the next poll request
                 * will get the new status from the database.
                 */
                String status = PushServletConstants.Status.COMPLETED.name();
                pushAuthStatusCacheManager.storeStatusCacheToDbOnly(pushAuthId, status);

                response.setStatus(HttpServletResponse.SC_OK);

                if (log.isDebugEnabled()) {
                    log.debug("Completed processing auth response from the device.");
                }
            }
        }
    }

    /**
     * Read the JSON content in the request.
     *
     * @param request HTTP request
     * @param response HTTP response
     * @return JSON content in the request
     */
    private JSONObject readJsonContentInRequest(HttpServletRequest request, HttpServletResponse response) {

        StringBuilder stringBuilder = new StringBuilder();
        String line;
        try (BufferedReader reader = request.getReader()) {
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line);
            }
        } catch (IOException e) {
            PushServletConstants.ErrorMessages error =
                    PushServletConstants.ErrorMessages.ERROR_CODE_REQUEST_CONTENT_READ_FAILED;
            log.error(error.getDescription(), e);
            handleAPIErrorResponse(response, error, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return null;
        }
        String jsonString = stringBuilder.toString();
        return new JSONObject(jsonString);
    }

    /**
     * Derive the Device ID from the auth response token header.
     *
     * @param token Auth response token
     * @param response HTTP response
     * @return Device ID
     */
    private String getDeviceIdFromToken(String token, HttpServletResponse response) {

        try {
            return String.valueOf(JWTParser.parse(token).getHeader().getCustomParam(
                    PushServletConstants.TOKEN_DEVICE_ID));
        } catch (ParseException e) {
            PushServletConstants.ErrorMessages error =
                    PushServletConstants.ErrorMessages.ERROR_CODE_GET_DEVICE_ID_FAILED;
            if (log.isDebugEnabled()) {
                log.debug(error.getDescription(), e);
            }
            handleAPIErrorResponse(response, error, HttpServletResponse.SC_BAD_REQUEST);
            return null;
        }
    }

    /**
     * Get the claims set from the auth response token.
     *
     * @param token    Auth response token
     * @param deviceId Device ID
     * @param response HTTP response
     * @return JWTClaimsSet
     */
    private JWTClaimsSet getClaimsSetFromAuthToken(String token, String deviceId, HttpServletResponse response) {

        try {
            String publicKey = PushServletDataHolder.getInstance().getDeviceHandlerService().getPublicKey(deviceId);
            return PushChallengeValidator.getValidatedClaimSet(token, publicKey);
        } catch (PushDeviceHandlerException e) {
            PushServletConstants.ErrorMessages error
                    = PushServletConstants.ErrorMessages.ERROR_CODE_GET_PUBLIC_KEY_FAILED;
            log.error(String.format(error.getDescription(), deviceId), e);
            handleAPIErrorResponse(response, error, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return null;
        } catch (PushTokenValidationException e) {
            PushServletConstants.ErrorMessages error
                    = PushServletConstants.ErrorMessages.ERROR_CODE_TOKEN_VALIDATION_FAILED;
            if (log.isDebugEnabled()) {
                log.debug(String.format(error.getDescription(), deviceId), e);
            }
            handleAPIErrorResponse(response, error, HttpServletResponse.SC_BAD_REQUEST);
            return null;
        }
    }

    /**
     * Add the received auth response token to the authentication context.
     *
     * @param pushAuthId Push authentication ID
     * @param token      Auth response token
     * @param response   HTTP response
     */
    private boolean addToContext(String pushAuthId, String token, HttpServletResponse response) {

        PushAuthContextManager contextManager = PushServletDataHolder.getInstance().getPushAuthContextManager();
        PushAuthContext context = contextManager.getContext(pushAuthId);
        if (context == null) {
            PushServletConstants.ErrorMessages error =
                    PushServletConstants.ErrorMessages.ERROR_CODE_ERROR_AUTH_CONTEXT_NOT_FOUND;
            if (log.isDebugEnabled()) {
                log.debug(String.format(error.getDescription(), pushAuthId));
            }
            handleAPIErrorResponse(response, error, HttpServletResponse.SC_BAD_REQUEST);
            return false;
        }

        // Invalidating the existing cache across the cluster.
        contextManager.clearContext(pushAuthId);

        // Store the new context with the updated token.
        context.setToken(token);
        contextManager.storeContext(pushAuthId, context);
        return true;
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
