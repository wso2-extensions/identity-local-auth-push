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

package org.wso2.carbon.identity.local.auth.push.authenticator.util;

import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.push.authenticator.exception.PushAuthenticatorServerException;
import org.wso2.carbon.identity.local.auth.push.authenticator.internal.AuthenticatorDataHolder;

import javax.servlet.http.HttpServletRequest;

/**
 * Utility class for the push authenticator.
 */
public class AuthenticatorUtils {

    /**
     * Get the multi option URI query param.
     *
     * @param request HttpServletRequest.
     * @return Query parameter for the multi option URI.
     */
    public static String getMultiOptionURIQueryString(HttpServletRequest request) {

        String multiOptionURI = "";
        if (request != null) {
            multiOptionURI = request.getParameter("multiOptionURI");
            multiOptionURI = multiOptionURI != null ? AuthenticatorConstants.MULTI_OPTION_URI_PARAM +
                    Encode.forUriComponent(multiOptionURI) : "";
        }
        return multiOptionURI;
    }

    /**
     * Mask the given value if it is required.
     *
     * @param value Value to be masked.
     * @return Masked/unmasked value.
     */
    public static String maskIfRequired(String value) {

        return LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(value) : value;
    }

    /**
     * Get the push authentication wait page URL.
     *
     * @return Push auth wait page URL.
     * @throws AuthenticationFailedException If an error occurred while building the URL.
     */
    public static String getPushAuthWaitPageUrl() throws AuthenticationFailedException {

        try {
            return ServiceURLBuilder.create()
                    .addPath(AuthenticatorConstants.PUSH_AUTH_WAIT_PAGE)
                    .build()
                    .getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building push authentication web page URL", e);
        }
    }

    /**
     * Get the registration page URL.
     *
     * @return Registration page URL.
     * @throws AuthenticationFailedException If an error occurred while building the URL.
     */
    public static String getRegistrationPageUrl() throws AuthenticationFailedException {

        try {
            return ServiceURLBuilder.create()
                    .addPath(AuthenticatorConstants.PUSH_DEVICE_REGISTRATION_PAGE)
                    .build()
                    .getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building registration page URL", e);
        }
    }

    /**
     * Get the push device enroll consent page URL.
     *
     * @return Push device enroll consent page URL.
     * @throws AuthenticationFailedException If an error occurred while building the URL.
     */
    public static String getPushDeviceEnrollConsentPageUrl() throws AuthenticationFailedException {

        try {
            return ServiceURLBuilder.create()
                    .addPath(AuthenticatorConstants.PUSH_DEVICE_ENROLL_CONSENT_PAGE)
                    .build()
                    .getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building push device enroll consent page URL", e);
        }
    }

    /**
     * Get push authentication error page URL.
     *
     * @return URL of the OTP error page.
     * @throws AuthenticationFailedException If an error occurred while getting the error page url.
     */
    public static String getPushAuthPErrorPageUrl() throws AuthenticationFailedException {

        try {
            return ServiceURLBuilder.create()
                    .addPath(AuthenticatorConstants.ERROR_PAGE)
                    .build()
                    .getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building push authentication error page URL", e);
        }
    }

    /**
     * Get the push authenticator configuration.
     *
     * @param key          Configuration key.
     * @param tenantDomain Tenant domain.
     * @return Configuration value.
     * @throws PushAuthenticatorServerException If an error occurred while getting the configuration.
     */
    public static String getPushAuthenticatorConfig(String key, String tenantDomain)
            throws PushAuthenticatorServerException {

        try {
            Property[] connectorConfigs;
            IdentityGovernanceService governanceService =
                    AuthenticatorDataHolder.getInstance().getIdentityGovernanceService();
            connectorConfigs = governanceService.getConfiguration(new String[]{key}, tenantDomain);
            return connectorConfigs[0].getValue();
        } catch (IdentityGovernanceException e) {
            throw handleServerException(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG, e,
                    (Object) null);
        }
    }

    /**
     * Get the PushAuthenticatorServerException with given error details.
     *
     * @param error     ErrorMessages.
     * @param throwable Throwable.
     * @param data      Meta data.
     * @return PushAuthenticatorServerException.
     */
    public static PushAuthenticatorServerException handleServerException(AuthenticatorConstants.ErrorMessages error,
                                                                         Throwable throwable, Object... data) {

        String message = error.getMessage();
        if (data != null) {
            message = String.format(message, data);
        }
        return new PushAuthenticatorServerException(error.getCode(), message, throwable);
    }
}
