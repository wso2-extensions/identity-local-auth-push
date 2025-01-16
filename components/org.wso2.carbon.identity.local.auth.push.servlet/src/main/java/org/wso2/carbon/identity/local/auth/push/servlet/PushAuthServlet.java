package org.wso2.carbon.identity.local.auth.push.servlet;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.local.auth.push.authenticator.PushAuthContextManager;
import org.wso2.carbon.identity.local.auth.push.authenticator.model.PushAuthContext;
import org.wso2.carbon.identity.local.auth.push.servlet.constant.PushServletConstants;
import org.wso2.carbon.identity.local.auth.push.servlet.impl.PushAuthStatusCacheManagerImpl;
import org.wso2.carbon.identity.local.auth.push.servlet.internal.PushServletDataHolder;
import org.wso2.carbon.identity.notification.push.common.PushChallengeValidator;
import org.wso2.carbon.identity.notification.push.common.exception.PushTokenValidationException;
import org.wso2.carbon.identity.notification.push.device.handler.exception.PushDeviceHandlerException;

import java.io.BufferedReader;
import java.io.IOException;
import java.text.ParseException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.local.auth.push.servlet.constant.PushServletConstants.AUTH_RESPONSE;

/**
 * Servlet for handling authentication requests sent from mobile device.
 */
public class PushAuthServlet extends HttpServlet {

    private static final long serialVersionUID = 3471640151205811758L;
    private static final Log log = LogFactory.getLog(PushAuthServlet.class);
    private static final PushAuthStatusCacheManager pushAuthStatusCacheManager = new PushAuthStatusCacheManagerImpl();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        handleMobileResponse(request, response);
    }

    private void handleMobileResponse(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        JSONObject jsonContent = readJsonContentInRequest(request);
        String token = jsonContent.getString(AUTH_RESPONSE);

        if (StringUtils.isBlank(token)) {

            if (log.isDebugEnabled()) {
                log.debug(PushServletConstants.ErrorMessages.ERROR_CODE_AUTH_RESPONSE_TOKEN_NOT_FOUND.toString());
            }

            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    PushServletConstants.ErrorMessages.ERROR_CODE_AUTH_RESPONSE_TOKEN_NOT_FOUND.toString());
        } else {

            String deviceId = getDeviceIdFromToken(token);
            JWTClaimsSet claimsSet = getClaimsSetFromAuthToken(token, deviceId);
            String pushAuthId;
            String tenantDomain;
            try {
                pushAuthId = claimsSet.getStringClaim(PushServletConstants.TOKEN_PUSH_AUTH_ID);
                tenantDomain = claimsSet.getStringClaim(PushServletConstants.TOKEN_TENANT_DOMAIN);
            } catch (ParseException e) {
                throw new ServletException(PushServletConstants.ErrorMessages.ERROR_CODE_PARSE_JWT_FAILED.toString());
            }

            if (StringUtils.isBlank(pushAuthId) || StringUtils.isBlank(tenantDomain)) {

                String errorMessage;
                if (StringUtils.isBlank(pushAuthId)) {
                    errorMessage = String.format(
                            PushServletConstants.ErrorMessages.ERROR_CODE_PUSH_AUTH_ID_NOT_FOUND.toString(), deviceId);
                } else {
                    errorMessage = String.format(
                            PushServletConstants.ErrorMessages.ERROR_CODE_TENANT_ID_NOT_FOUND.toString(), deviceId);
                }
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage);
                }
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, errorMessage);
            } else {

                addToContext(pushAuthId, token);
                String status = PushServletConstants.Status.COMPLETED.name();
                pushAuthStatusCacheManager.storeStatusCache(pushAuthId, status);

                response.setStatus(HttpServletResponse.SC_OK);

                if (log.isDebugEnabled()) {
                    log.debug("Completed processing auth response from mobile app.");
                }
            }
        }
    }

    /**
     * Read the JSON content in the request.
     *
     * @param request HTTP request
     * @return JSON content in the request
     */
    private JSONObject readJsonContentInRequest(HttpServletRequest request) {

        StringBuilder stringBuilder = new StringBuilder();
        String line;
        try (BufferedReader reader = request.getReader()) {
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        String jsonString = stringBuilder.toString();
        return new JSONObject(jsonString);
    }

    /**
     * Derive the Device ID from the auth response token header.
     *
     * @param token Auth response token
     * @return Device ID
     * @throws ServletException if the token string fails to parse to JWT
     */
    private String getDeviceIdFromToken(String token) throws ServletException {

        try {
            return String.valueOf(JWTParser.parse(token).getHeader().getCustomParam(
                    PushServletConstants.TOKEN_DEVICE_ID));
        } catch (ParseException e) {
            throw new ServletException(PushServletConstants
                    .ErrorMessages.ERROR_CODE_GET_DEVICE_ID_FAILED.toString(), e);
        }
    }

    /**
     * Get the claims set from the auth response token.
     *
     * @param token    Auth response token
     * @param deviceId Device ID
     * @return JWTClaimsSet
     * @throws ServletException if the public key cannot be retrieved or the token validation fails
     */
    private JWTClaimsSet getClaimsSetFromAuthToken(String token, String deviceId) throws ServletException {

        try {
            String publicKey = PushServletDataHolder.getInstance().getDeviceHandlerService().getPublicKey(deviceId);
            return PushChallengeValidator.getValidatedClaimSet(token, publicKey);
        } catch (PushDeviceHandlerException e) {
            String errorMessage = String.format(PushServletConstants
                    .ErrorMessages.ERROR_CODE_GET_PUBLIC_KEY_FAILED.toString(), deviceId);
            throw new ServletException(errorMessage);
        } catch (PushTokenValidationException e) {
            String errorMessage = String.format(PushServletConstants
                    .ErrorMessages.ERROR_CODE_TOKEN_VALIDATION_FAILED.toString(), deviceId);
            throw new ServletException(errorMessage);
        }
    }

    /**
     * Add the received auth response token to the authentication context.
     *
     * @param pushAuthId   Push authentication ID
     * @param token        Auth response token
     */
    private void addToContext(String pushAuthId, String token) {

        PushAuthContextManager contextManager = PushServletDataHolder.getInstance().getPushAuthContextManager();
        PushAuthContext context = contextManager.getContext(pushAuthId);
        context.setToken(token);
        contextManager.storeContext(pushAuthId, context);
    }
}
