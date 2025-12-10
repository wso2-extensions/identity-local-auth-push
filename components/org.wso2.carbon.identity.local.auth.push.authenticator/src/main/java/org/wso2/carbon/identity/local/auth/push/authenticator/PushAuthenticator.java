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

package org.wso2.carbon.identity.local.auth.push.authenticator;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AdditionalData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.push.authenticator.context.PushAuthContextManager;
import org.wso2.carbon.identity.local.auth.push.authenticator.context.PushAuthContextManagerImpl;
import org.wso2.carbon.identity.local.auth.push.authenticator.exception.PushAuthenticatorServerException;
import org.wso2.carbon.identity.local.auth.push.authenticator.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.push.authenticator.model.PushAuthContext;
import org.wso2.carbon.identity.local.auth.push.authenticator.util.AuthenticatorUtils;
import org.wso2.carbon.identity.notification.push.common.PushChallengeValidator;
import org.wso2.carbon.identity.notification.push.common.exception.PushTokenValidationException;
import org.wso2.carbon.identity.notification.push.device.handler.exception.PushDeviceHandlerException;
import org.wso2.carbon.identity.notification.push.device.handler.model.Device;
import org.wso2.carbon.identity.notification.push.device.handler.model.RegistrationDiscoveryData;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import ua_parser.Client;
import ua_parser.Parser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.AUTH_ERROR_MSG;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.RequestParams.IS_IDF_INITIATED_FROM_AUTHENTICATOR;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_NON_BASIC_AUTHENTICATION;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.OPERATION_STATUS;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.TENANT_DOMAIN;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.AUTHENTICATORS;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.AUTHENTICATORS_QUERY_PARAM;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.AUTHENTICATOR_MESSAGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.AUTH_REQUEST_STATUS_APPROVED;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.AUTH_REQUEST_STATUS_DENIED;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.CHALLENGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ConnectorConfig.ENABLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ConnectorConfig.ENABLE_PUSH_NUMBER_CHALLENGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ConnectorConfig.RESEND_NOTIFICATION_MAX_ATTEMPTS;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.DEVICE_ID;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.DEVICE_TOKEN;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ENROLL_DATA_PARAM;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ERROR_NUMBER_CHALLENGE_FAILED_QUERY_PARAMS;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ERROR_PUSH_AUTHENTICATION_FAILED;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ERROR_PUSH_INTERNAL_ERROR_QUERY_PARAMS;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ERROR_TOKEN_RESPONSE_FAILURE_QUERY_PARAMS;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ERROR_USER_DENIED_CONSENT_QUERY_PARAMS;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ERROR_USER_REGISTERED_DEVICE_NOT_FOUND;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ERROR_USER_RESEND_COUNT_EXCEEDED_QUERY_PARAMS;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_AUTHENTICATION_CONTEXT_NOT_FOUND;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_CLAIMSET_NOT_FOUND_IN_RESPONSE_TOKEN;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_DEVICE_ID_NOT_FOUND;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_EMPTY_USERNAME;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_BUILDING_STATUS_URL;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_ACCOUNT_UNLOCK_TIME;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_AUTH_STATUS_FROM_TOKEN;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_FEDERATED_AUTHENTICATOR;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_REGISTRATION_DATA;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_DEVICE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_DEVICE_PUBLIC_KEY;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_ID;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_REALM;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_INVALID_AUTH_STATUS_FROM_TOKEN;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_DEVICE_REGISTRATION_PAGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_IDF_PAGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_LOGIN_PAGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_GETTING_ACCOUNT_STATE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_USER_FOUND;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_PUSH_AUTH_CHALLENGE_VALIDATION_FAILED;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_PUSH_AUTH_CONTEXT_NOT_FOUND;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_PUSH_AUTH_ID_NOT_FOUND;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_PUSH_AUTH_RESPONSE_TOKEN_NOT_FOUND;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_PUSH_AUTH_USER_DENIED;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_PUSH_NUMBER_CHALLENGE_VALIDATION_FAILED;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_RESPONSE_TOKEN_VALIDATION_FAILED;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_RETRYING_PUSH_NOTIFICATION_RESEND;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_USER_ACCOUNT_LOCKED;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.IDF_HANDLER_NAME;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.INVALID_USERNAME;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.IP_ADDRESS;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.IS_DEVICE_REGISTRATION_ENGAGED;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.IS_LOGIN_ATTEMPT_BY_INVALID_USER;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.LOCAL_AUTHENTICATOR;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.NOTIFICATION_PROVIDER;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.NOTIFICATION_RESEND_ATTEMPTS;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.NOTIFICATION_SCENARIO;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.NUMBER_CHALLENGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.NUMBER_CHALLENGE_PARAM;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PASSWORD;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTHENTICATOR_I18_KEY;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTH_FAILED_ATTEMPTS_CLAIM;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTH_FAIL_INTERNAL_ERROR;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTH_FAIL_NUMBER_CHALLENGE_FAILED;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTH_FAIL_TOKEN_RESPONSE_FAILED;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTH_FAIL_USER_DENIED;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTH_ID;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTH_ID_PARAM;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_ID;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_NOTIFICATION_CHANNEL;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_NOTIFICATION_EVENT_NAME;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_NOTIFICATION_SENT;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.REQUEST_DEVICE_BROWSER;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.REQUEST_DEVICE_OS;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.RETRY_QUERY_PARAMS;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.SCENARIO;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ScenarioTypes.CANCEL_PUSH_ENROLL;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ScenarioTypes.INIT_PUSH_ENROLL;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ScenarioTypes.LOGOUT;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ScenarioTypes.PROCEED_PUSH_AUTHENTICATION;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ScenarioTypes.PUSH_AUTHENTICATION;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ScenarioTypes.PUSH_DEVICE_ENROLLMENT;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ScenarioTypes.RESEND_PUSH_NOTIFICATION;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ScenarioTypes.SEND_PUSH_NOTIFICATION;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.TOKEN_AUTH_CHALLENGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.TOKEN_AUTH_STATUS;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.TOKEN_NUMBER_CHALLENGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.UNLOCK_QUERY_PARAM;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.USERNAME;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.USERNAME_PARAM;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.USER_AGENT;
import static org.wso2.carbon.identity.local.auth.push.authenticator.util.AuthenticatorUtils.getPushAuthPErrorPageUrl;
import static org.wso2.carbon.identity.local.auth.push.authenticator.util.AuthenticatorUtils.getPushAuthWaitPageUrl;
import static org.wso2.carbon.identity.local.auth.push.authenticator.util.AuthenticatorUtils.getPushDeviceEnrollConsentPageUrl;
import static org.wso2.carbon.identity.local.auth.push.authenticator.util.AuthenticatorUtils.getRegistrationPageUrl;
import static org.wso2.carbon.identity.notification.push.device.handler.constant.PushDeviceHandlerConstants.ErrorMessages.ERROR_CODE_DEVICE_NOT_FOUND_FOR_USER_ID;
import static org.wso2.carbon.user.core.UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;

/**
 * Authenticator for Push Notification based authentication.
 */
public class PushAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = -1130478454035179733L;
    private static final Log LOG = LogFactory.getLog(PushAuthenticator.class);
    private static PushAuthContextManager pushAuthContextManager = new PushAuthContextManagerImpl();

    @Override
    public boolean canHandle(HttpServletRequest request) {

        boolean isUsernameAvailable = StringUtils.isNotBlank(request.getParameter(USERNAME));
        boolean isScenarioAvailable = StringUtils.isNotBlank(request.getParameter(SCENARIO)) &&
                (PROCEED_PUSH_AUTHENTICATION.getValue().equals(request.getParameter(SCENARIO)) ||
                        RESEND_PUSH_NOTIFICATION.getValue().equals(request.getParameter(SCENARIO)) ||
                        SEND_PUSH_NOTIFICATION.getValue().equals(request.getParameter(SCENARIO)) ||
                        INIT_PUSH_ENROLL.getValue().equals(request.getParameter(SCENARIO)) ||
                        CANCEL_PUSH_ENROLL.getValue().equals(request.getParameter(SCENARIO)) ||
                        PUSH_DEVICE_ENROLLMENT.getValue().equals(request.getParameter(SCENARIO)));

        boolean canHandle = isScenarioAvailable || isUsernameAvailable;

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("PushAuthenticator canHandle check: isUsernameAvailable=%s, " +
                            "isScenarioAvailable=%s, scenario=%s, canHandle=%s",
                    isUsernameAvailable, isScenarioAvailable, request.getParameter(SCENARIO), canHandle));
        }

        return canHandle;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        AuthenticatorConstants.ScenarioTypes scenario = resolveScenario(request, context);

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Processing PushAuthenticator with scenario: %s", scenario));
        }

        switch (scenario) {
            case LOGOUT:
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            case SEND_PUSH_NOTIFICATION:
            case PUSH_DEVICE_ENROLLMENT:
                initiateAuthenticationRequest(request, response, context);
                return AuthenticatorFlowStatus.INCOMPLETE;
            case INIT_PUSH_ENROLL:
                context.setProperty(IS_DEVICE_REGISTRATION_ENGAGED, true);
                return AuthenticatorFlowStatus.FAIL_COMPLETED;
            case CANCEL_PUSH_ENROLL:
                return AuthenticatorFlowStatus.FAIL_COMPLETED;
            default:
                // PROCEED_PUSH_AUTHENTICATION and RESEND_PUSH_NOTIFICATION are handled here.
                return super.process(request, response, context);
        }
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUserFromContext = getAuthenticatedUserFromContext(context);
        String tenantDomain = context.getTenantDomain();

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Initiating authentication request for tenantDomain: %s, " +
                            "authenticatedUserFromContext: %s", tenantDomain,
                    authenticatedUserFromContext != null ? AuthenticatorUtils.maskIfRequired(
                            authenticatedUserFromContext.getUserName()) : "null"));
        }

        if (authenticatedUserFromContext == null) {

            /*
             * If an authenticatedUser is not found in the context, and the user is not redirected from the
             * Identifier First handler, redirect the user to the Identifier First page.
             */
            if (!isUserRedirectedFromIDF(request)) {
                LOG.debug("No authenticated user found in context and not redirected from IDF. " +
                        "Redirecting to IDF page.");
                redirectUserToIDF(request, response, context);
                context.setProperty(IS_IDF_INITIATED_FROM_AUTHENTICATOR, true);
                return;
            }

            // If the request is returned from the Identifier First page, resolve the user and set them in context.
            LOG.debug("Request returned from IDF page. Resolving user from request.");
            context.removeProperty(IS_IDF_INITIATED_FROM_AUTHENTICATOR);
            AuthenticatedUser authenticatedUser = resolveUserFromRequest(request, context);
            authenticatedUserFromContext = resolveUserFromUserStore(authenticatedUser, context);
            setResolvedUserInContext(context, authenticatedUserFromContext);

        } else if (isPreviousIdPAuthenticationFlowHandler(context)) {

            /*
             * If the previous authentication has only been done by AuthenticationFlowHandlers, need to check if the
             * user exists in the database.
             */
            LOG.debug("Previous authentication done by AuthenticationFlowHandler. Resolving user from user store.");
            authenticatedUserFromContext = resolveUserFromUserStore(authenticatedUserFromContext, context);
            setResolvedUserInContext(context, authenticatedUserFromContext);
        }

        // If the authenticated user is still null at this point, then an invalid user is trying to log in.
        if (authenticatedUserFromContext == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Invalid user attempting to login: %s",
                        AuthenticatorUtils.maskIfRequired(request.getParameter(USERNAME))));
            }
            AuthenticatedUser invalidUser = new AuthenticatedUser();
            invalidUser.setUserName(request.getParameter(USERNAME));
            context.setProperty(IS_LOGIN_ATTEMPT_BY_INVALID_USER, true);
            context.setProperty(INVALID_USERNAME, request.getParameter(USERNAME));
            String randomPushAuthId = UUID.randomUUID().toString();
            Random random = new Random();
            redirectToPushAuthWaitPage(invalidUser, response, request, context, randomPushAuthId,
                    Integer.toString(random.nextInt(100)));
            return;
        }

        /*
         * If we reach this point, a valid user is trying to log in.
         */
        context.removeProperty(IS_LOGIN_ATTEMPT_BY_INVALID_USER);
        context.removeProperty(INVALID_USERNAME);

        /*
         * We need to identify the username that the server is using to identify the user. This is needed to handle
         * federated scenarios, since for federated users, the username in the authentication context is not same as the
         * username when the user is provisioned to the server.
         */
        String mappedLocalUsername = getMappedLocalUsername(authenticatedUserFromContext, context);
        /*
         * If the mappedLocalUsername is blank, that means this is an initial login attempt by a non-provisioned
         * federated user.
         */
        boolean isInitialFederationAttempt = StringUtils.isBlank(mappedLocalUsername);

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("User resolution - mappedLocalUsername: %s, isInitialFederationAttempt: %s, " +
                            "isFederatedUser: %s", AuthenticatorUtils.maskIfRequired(mappedLocalUsername),
                    isInitialFederationAttempt, authenticatedUserFromContext.isFederatedUser()));
        }

        AuthenticatedUser authenticatingUser = resolveAuthenticatingUser(authenticatedUserFromContext,
                mappedLocalUsername, tenantDomain, isInitialFederationAttempt);

        try {
            if (!isInitialFederationAttempt
                    && AuthenticatorDataHolder.getInstance().getAccountLockService().isAccountLocked(
                    authenticatingUser.getUserName(),
                    authenticatingUser.getTenantDomain(),
                    authenticatingUser.getUserStoreDomain())
            ) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(String.format("User account is locked: %s",
                            AuthenticatorUtils.maskIfRequired(authenticatingUser.getUserName())));
                }
                handleScenarioForLockedUser(authenticatingUser, request, response, context);
                return;
            }
        } catch (AccountLockServiceException e) {
            String error = String.format(
                    ERROR_CODE_GETTING_ACCOUNT_STATE.getMessage(),
                    AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName()));
            throw new AuthenticationFailedException(ERROR_CODE_GETTING_ACCOUNT_STATE.getCode(), error, e);
        }

        String pushAuthId = UUID.randomUUID().toString();

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Generated pushAuthId: %s for user: %s", pushAuthId,
                    AuthenticatorUtils.maskIfRequired(authenticatingUser.getUserName())));
        }

        PushAuthContext pushAuthContext = new PushAuthContext();

        AuthenticatorConstants.ScenarioTypes scenario = resolveScenario(request, context);
        if (scenario == SEND_PUSH_NOTIFICATION || scenario == RESEND_PUSH_NOTIFICATION
                || scenario == PUSH_DEVICE_ENROLLMENT) {

            // Check if the user has exceeded the maximum number of resend attempts.
            if (scenario == RESEND_PUSH_NOTIFICATION && context.getProperty(NOTIFICATION_RESEND_ATTEMPTS) != null) {
                if (StringUtils.isNotBlank(context.getProperty(NOTIFICATION_RESEND_ATTEMPTS).toString())) {
                    int allowedResendAttemptsCount = getMaximumResendAttempts(tenantDomain);
                    if ((int) context.getProperty(NOTIFICATION_RESEND_ATTEMPTS) >= allowedResendAttemptsCount) {
                        LOG.debug("User has exceeded maximum resend attempts. Failing authentication.");
                        handlePushAuthFailedScenario(request, response, context,
                                ERROR_USER_RESEND_COUNT_EXCEEDED_QUERY_PARAMS);
                        return;
                    }
                }
            }

            Device device;
            try {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(String.format("Attempting to retrieve device for user: %s in tenantDomain: %s",
                            AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName()),
                            tenantDomain));
                }
                device = AuthenticatorDataHolder.getInstance().getDeviceHandlerService()
                        .getDeviceByUserId(authenticatedUserFromContext.getUserId(), tenantDomain);
            } catch (UserIdNotFoundException e) {
                String error = String.format(
                        ERROR_CODE_ERROR_GETTING_USER_ID.getMessage(),
                        AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName()));
                throw new AuthenticationFailedException(ERROR_CODE_ERROR_GETTING_USER_ID.getCode(),
                        error, e);
            } catch (PushDeviceHandlerException e) {
                if (ERROR_CODE_DEVICE_NOT_FOUND_FOR_USER_ID.getCode().equals(e.getErrorCode())) {
                    // The user does not have a device registered.
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(String.format("No device found for user: %s",
                                AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName())));
                    }
                    device = null;
                } else {
                    String error = String.format(
                            ERROR_CODE_ERROR_GETTING_USER_DEVICE.getMessage(),
                            AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName()));
                    throw new AuthenticationFailedException(ERROR_CODE_ERROR_GETTING_USER_DEVICE.getCode(),
                            error, e);
                }
            }

            // If device is null, that means the user does not have a device registered.
            if (device == null) {

                // Check if push device progressive enrollment is enabled.
                if (!isProgressiveDeviceEnrollmentEnabled(tenantDomain)) {
                    LOG.debug("Progressive device enrollment is not enabled. Failing authentication.");
                    handlePushAuthFailedScenario(request, response, context, ERROR_USER_REGISTERED_DEVICE_NOT_FOUND);
                    return;
                }

                if (isUserRedirectedFromIDF(request)) {

                    if (context.getProperty(IS_DEVICE_REGISTRATION_ENGAGED) != null && Boolean.TRUE.equals(
                            context.getProperty(IS_DEVICE_REGISTRATION_ENGAGED))) {
                        LOG.debug("Device registration already engaged. Clearing registration flag.");
                        context.removeProperty(IS_DEVICE_REGISTRATION_ENGAGED);
                    } else {
                        // If there is no device registered for the user, and the user is redirected from the Identifier
                        // then, get consent from the user to register a device.
                        LOG.debug("Redirecting user to device enrollment consent page.");
                        handleIDFUserDeviceEnrolEngageScenario(
                                authenticatedUserFromContext, response, request, context);
                        if (!StringUtils.isEmpty(request.getParameter(USERNAME))) {
                            persistUsername(context, request.getParameter(USERNAME));
                        }
                        context.setProperty(IS_DEVICE_REGISTRATION_ENGAGED, true);
                        return;
                    }
                }

                try {
                    LOG.debug("Retrieving registration discovery data for device enrollment.");
                    RegistrationDiscoveryData registrationData = AuthenticatorDataHolder.getInstance()
                            .getDeviceHandlerService().getRegistrationDiscoveryData(
                                    authenticatedUserFromContext.toFullQualifiedUsername(), tenantDomain);
                    String encodedData = Base64.getEncoder().encodeToString(registrationData.buildJSON().getBytes());
                    LOG.debug("Redirecting user to device registration page.");
                    redirectToRegistrationPage(authenticatedUserFromContext, response, request, context, encodedData);
                    return;

                } catch (PushDeviceHandlerException e) {
                    String error = String.format(
                            ERROR_CODE_ERROR_GETTING_REGISTRATION_DATA.getMessage(),
                            AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName()));
                    throw new AuthenticationFailedException(ERROR_CODE_ERROR_GETTING_REGISTRATION_DATA.getCode(),
                            error, e);
                }
            }

            // If the code reaches this point, the user has a device registered.
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Device found for user: %s, deviceId: %s",
                        AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName()),
                        device.getDeviceId()));
            }
            prepareAuthChallenges(pushAuthContext, tenantDomain);
            pushAuthContext.setDeviceId(device.getDeviceId());
            pushAuthContext.setScenario(PUSH_AUTHENTICATION.getValue());
            pushAuthContextManager.storeContext(pushAuthId, pushAuthContext);
            context.setProperty(PUSH_AUTH_ID, pushAuthId);

            try {
                LOG.debug("Triggering push notification event.");
                triggerNotificationEvent(context, authenticatedUserFromContext, device, pushAuthContext, request);
                if (LOG.isDebugEnabled()) {
                    LOG.debug(String.format("Push notification triggered successfully for user: %s, pushAuthId: %s",
                            AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName()),
                            pushAuthId));
                }
            } catch (IdentityEventException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(String.format("Failed to trigger push notification event for user: %s",
                            AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName())), e);
                }
                pushAuthContextManager.clearContext(PUSH_AUTH_ID);
                context.removeProperty(PUSH_AUTH_ID);
                handleNotificationEventFailureScenario(request, response, context);
                return;
            }

            if (scenario == RESEND_PUSH_NOTIFICATION) {
                LOG.debug("Resending push notification. Updating resend count.");
                updateResendCount(context);
            }
        }

        redirectToPushAuthWaitPage(authenticatedUserFromContext, response, request, context, pushAuthId,
                pushAuthContext.getNumberChallenge());
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUserFromContext = getAuthenticatedUserFromContext(context);
        if (authenticatedUserFromContext == null) {
            throw handleAuthErrorScenario(ERROR_CODE_NO_USER_FOUND);
        }
        String tenantDomain = context.getTenantDomain();

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Processing authentication response for user: %s in tenantDomain: %s",
                    AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName()), tenantDomain));
        }

        /*
         * We need to identify the username that the server is using to identify the user. This is needed to handle
         * federated scenarios, since for federated users, the username in the authentication context is not same as the
         * username when the user is provisioned to the server.
         */
        String mappedLocalUsername = getMappedLocalUsername(authenticatedUserFromContext, context);
        /*
         * If the mappedLocalUsername is blank, that means this is an initial login attempt by a non-provisioned
         * federated user.
         */
        boolean isInitialFederationAttempt = StringUtils.isBlank(mappedLocalUsername);

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Authentication response - mappedLocalUsername: %s, " +
                            "isInitialFederationAttempt: %s", AuthenticatorUtils.maskIfRequired(mappedLocalUsername),
                    isInitialFederationAttempt));
        }

        AuthenticatedUser authenticatingUser = resolveAuthenticatingUser(authenticatedUserFromContext,
                mappedLocalUsername, tenantDomain, isInitialFederationAttempt);
        try {
            if (!isInitialFederationAttempt
                    && AuthenticatorDataHolder.getInstance().getAccountLockService().isAccountLocked(
                    authenticatingUser.getUserName(), authenticatingUser.getTenantDomain(),
                    authenticatingUser.getUserStoreDomain())) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(String.format("User account is locked during response processing: %s",
                            AuthenticatorUtils.maskIfRequired(authenticatingUser.getUserName())));
                }
                throw handleAuthErrorScenario(ERROR_CODE_USER_ACCOUNT_LOCKED,
                        AuthenticatorUtils.maskIfRequired(authenticatingUser.getUserName()));
            }
        } catch (AccountLockServiceException e) {
            handlePushAuthFailedScenario(request, response, context, ERROR_PUSH_INTERNAL_ERROR_QUERY_PARAMS);
            throw handleAuthErrorScenario(PUSH_AUTH_FAIL_INTERNAL_ERROR, context,
                    ERROR_CODE_GETTING_ACCOUNT_STATE, e);
        }

        String pushAuthId = context.getProperty(PUSH_AUTH_ID).toString();
        if (StringUtils.isBlank(pushAuthId)) {
            LOG.debug("PushAuthId not found in context.");
            handlePushAuthFailedScenario(request, response, context, ERROR_PUSH_INTERNAL_ERROR_QUERY_PARAMS);
            throw handleAuthErrorScenario(PUSH_AUTH_FAIL_INTERNAL_ERROR,
                    context, ERROR_CODE_PUSH_AUTH_ID_NOT_FOUND);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Processing response for pushAuthId: %s", pushAuthId));
        }

        PushAuthContext pushAuthContext = pushAuthContextManager.getContext(pushAuthId);
        if (pushAuthContext == null) {
            LOG.debug("PushAuthContext not found in cache.");
            handlePushAuthFailedScenario(request, response, context, ERROR_PUSH_INTERNAL_ERROR_QUERY_PARAMS);
            throw handleAuthErrorScenario(PUSH_AUTH_FAIL_INTERNAL_ERROR,
                    context, ERROR_CODE_PUSH_AUTH_CONTEXT_NOT_FOUND,
                    AuthenticatorUtils.maskIfRequired(authenticatingUser.getUserName()));
        }

        // If user requests a resend, throw an error. The resend is handled at the framework level.
        if (StringUtils.isNotBlank(request.getParameter(SCENARIO)) &&
                RESEND_PUSH_NOTIFICATION.getValue().equals(request.getParameter(SCENARIO))) {
            // Clear the push auth context created for this particular push auth flow.
            pushAuthContextManager.clearContext(pushAuthId);
            context.removeProperty(PUSH_AUTH_ID);
            throw handleAuthErrorScenario(ERROR_CODE_RETRYING_PUSH_NOTIFICATION_RESEND,
                    AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName()));
        }

        String authResponseToken = pushAuthContext.getToken();
        if (StringUtils.isBlank(authResponseToken)) {
            LOG.debug("Authentication response token not found in push auth context.");
            handlePushAuthFailedScenario(request, response, context, ERROR_PUSH_INTERNAL_ERROR_QUERY_PARAMS);
            throw handleAuthErrorScenario(PUSH_AUTH_FAIL_INTERNAL_ERROR, context,
                    ERROR_CODE_PUSH_AUTH_RESPONSE_TOKEN_NOT_FOUND,
                    AuthenticatorUtils.maskIfRequired(authenticatingUser.getUserName()));
        }

        String deviceId = pushAuthContext.getDeviceId();
        if (StringUtils.isBlank(deviceId)) {
            LOG.debug("DeviceId not found in push auth context.");
            handlePushAuthFailedScenario(request, response, context, ERROR_PUSH_INTERNAL_ERROR_QUERY_PARAMS);
            throw handleAuthErrorScenario(PUSH_AUTH_FAIL_TOKEN_RESPONSE_FAILED, context,
                    ERROR_CODE_DEVICE_ID_NOT_FOUND,
                    AuthenticatorUtils.maskIfRequired(authenticatingUser.getUserName()));
        }

        String publicKey;
        try {
            publicKey = AuthenticatorDataHolder.getInstance().getDeviceHandlerService().getPublicKey(deviceId);
            LOG.debug("Public key retrieved successfully for device.");
        } catch (PushDeviceHandlerException e) {
            LOG.debug("Failed to retrieve public key for device.");
            handlePushAuthFailedScenario(request, response, context, ERROR_PUSH_INTERNAL_ERROR_QUERY_PARAMS);
            throw handleAuthErrorScenario(PUSH_AUTH_FAIL_INTERNAL_ERROR, context,
                    ERROR_CODE_ERROR_GETTING_USER_DEVICE_PUBLIC_KEY,
                    AuthenticatorUtils.maskIfRequired(authenticatingUser.getUserName()));
        }

        JWTClaimsSet claimsSet;
        try {
            LOG.debug("Validating JWT claims from response token.");
            claimsSet = PushChallengeValidator.getValidatedClaimSet(authResponseToken, publicKey);
            if (claimsSet == null) {
                LOG.debug("ClaimSet is null after validation.");
                handlePushAuthFailedScenario(request, response, context, ERROR_TOKEN_RESPONSE_FAILURE_QUERY_PARAMS);
                throw handleAuthErrorScenario(PUSH_AUTH_FAIL_TOKEN_RESPONSE_FAILED, context,
                        ERROR_CODE_CLAIMSET_NOT_FOUND_IN_RESPONSE_TOKEN, deviceId);
            }
            LOG.debug("JWT claims validated successfully.");
        } catch (PushTokenValidationException e) {
            LOG.debug("Failed to validate response token", e);
            handlePushAuthFailedScenario(request, response, context, ERROR_TOKEN_RESPONSE_FAILURE_QUERY_PARAMS);
            throw handleAuthErrorScenario(PUSH_AUTH_FAIL_TOKEN_RESPONSE_FAILED, context,
                    ERROR_CODE_RESPONSE_TOKEN_VALIDATION_FAILED, deviceId);
        }

        String authChallengeFromContext = pushAuthContext.getChallenge();
        if (!PushChallengeValidator.validateChallenge(claimsSet, TOKEN_AUTH_CHALLENGE,
                authChallengeFromContext, deviceId)) {
            LOG.debug("Validating auth challenge from response token failed.");
            handlePushAuthFailedScenario(request, response, context, ERROR_PUSH_AUTHENTICATION_FAILED);
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Push authentication request for user: %s failed due to challenge validation.",
                        authenticatedUserFromContext.getUserName()));
            }
            throw handleAuthErrorScenario(PUSH_AUTH_FAIL_TOKEN_RESPONSE_FAILED, context,
                    ERROR_CODE_PUSH_AUTH_CHALLENGE_VALIDATION_FAILED, deviceId);
        }
        LOG.debug("Auth challenge validated successfully");

        String authStatus;
        try {
            authStatus = PushChallengeValidator.getClaimFromClaimSet(claimsSet, TOKEN_AUTH_STATUS, deviceId);
        } catch (PushTokenValidationException e) {
            handlePushAuthFailedScenario(request, response, context, ERROR_TOKEN_RESPONSE_FAILURE_QUERY_PARAMS);
            throw handleAuthErrorScenario(PUSH_AUTH_FAIL_TOKEN_RESPONSE_FAILED, context,
                    ERROR_CODE_ERROR_GETTING_AUTH_STATUS_FROM_TOKEN, deviceId);
        }
        // Throw error when status is neither APPROVED nor DENIED.
        if (!AUTH_REQUEST_STATUS_APPROVED.equalsIgnoreCase(authStatus)
                && !AUTH_REQUEST_STATUS_DENIED.equalsIgnoreCase(authStatus)) {

            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Invalid auth status received: %s", authStatus));
            }
            handlePushAuthFailedScenario(request, response, context, ERROR_TOKEN_RESPONSE_FAILURE_QUERY_PARAMS);
            throw handleAuthErrorScenario(PUSH_AUTH_FAIL_TOKEN_RESPONSE_FAILED, context,
                    ERROR_CODE_ERROR_INVALID_AUTH_STATUS_FROM_TOKEN, deviceId);
        }

        if (AUTH_REQUEST_STATUS_APPROVED.equals(authStatus)) {

            LOG.debug("Auth status is APPROVED. Processing approval.");
            if (isNumberChallengeEnabled(tenantDomain)) {
                LOG.debug("Number challenge is enabled. Validating number challenge.");
                String numberChallengeFromContext = pushAuthContext.getNumberChallenge();
                boolean isNumberChallengeSuccessful = PushChallengeValidator.validateChallenge(claimsSet,
                        TOKEN_NUMBER_CHALLENGE, numberChallengeFromContext, deviceId);
                if (!isNumberChallengeSuccessful) {
                    LOG.debug("Number challenge validation failed.");
                    // Initiate authentication failure handling.
                    handlePushAuthVerificationFail(authenticatingUser, isInitialFederationAttempt);
                    handlePushAuthFailedScenario(request, response, context,
                            ERROR_NUMBER_CHALLENGE_FAILED_QUERY_PARAMS);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(String.format("Push authentication request for user: %s failed due to number " +
                                "challenge validation.", authenticatedUserFromContext.getUserName()));
                    }
                    throw handleAuthErrorScenario(
                            PUSH_AUTH_FAIL_NUMBER_CHALLENGE_FAILED,
                            context, ERROR_CODE_PUSH_NUMBER_CHALLENGE_VALIDATION_FAILED, deviceId);
                }
                LOG.debug("Number challenge validated successfully.");
            }

            // It reached here means, the authentication is successful.
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("User: %s authenticated successfully via push notification.",
                        authenticatedUserFromContext.getUserName()));
            }
            resetAuthFailedAttempts(authenticatingUser, isInitialFederationAttempt);
            context.setSubject(authenticatedUserFromContext);
            pushAuthContextManager.clearContext(pushAuthId);
            context.removeProperty(PUSH_AUTH_ID);
            return;

        } else if (AUTH_REQUEST_STATUS_DENIED.equals(authStatus)) {

            handlePushAuthFailedScenario(request, response, context, ERROR_USER_DENIED_CONSENT_QUERY_PARAMS);
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("User: %s denied the push notification authentication of pushAuthId: %s.",
                        authenticatedUserFromContext.getUserName(), pushAuthId));
            }
            pushAuthContextManager.clearContext(pushAuthId);
            context.removeProperty(PUSH_AUTH_ID);

            // At this point, authentication is failed. Hence, initiate authentication failure handling.
            handlePushAuthVerificationFail(authenticatingUser, isInitialFederationAttempt);
            throw handleAuthErrorScenario(PUSH_AUTH_FAIL_USER_DENIED, context,
                    ERROR_CODE_PUSH_AUTH_USER_DENIED, authenticatingUser.getUserName());
        }
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getRequestedSessionId();
    }

    @Override
    public String getName() {

        return PUSH_AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return PUSH_AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getI18nKey() {

        return PUSH_AUTHENTICATOR_I18_KEY;
    }

    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setDisplayName(getFriendlyName());
        String idpName = null;

        AuthenticatedUser authenticatedUser = null;
        if (context != null && context.getExternalIdP() != null) {
            idpName = context.getExternalIdP().getIdPName();
            authenticatedUser = context.getLastAuthenticatedUser();
        }

        authenticatorData.setIdp(idpName);
        authenticatorData.setI18nKey(PUSH_AUTHENTICATOR_I18_KEY);

        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.INTERNAL_PROMPT);

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        authenticatorData.setAuthParams(authenticatorParamMetadataList);

        // To show additional data, it requires at least one required param. So we have added scenario as required
        // param. To continue the push flow, the scenario should be PROCEED_PUSH_AUTHENTICATION.
        List<String> requiredParams = new ArrayList<>();
        requiredParams.add(SCENARIO);
        authenticatorData.setRequiredParams(requiredParams);

        PushAuthContext pushAuthContext = getPushAuthContext(context);
        authenticatorData.setAdditionalData(getAdditionalData(context, pushAuthContext));
        return Optional.of(authenticatorData);
    }

    /**
     * This method is used to persist the username in the context.
     *
     * @param context  The authentication context.
     * @param username The username provided by the user.
     */
    private void persistUsername(AuthenticationContext context, String username) {

        Map<String, String> identifierParams = new HashMap<>();
        identifierParams.put(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME, username);
        Map<String, Map<String, String>> contextParams = new HashMap<>();
        contextParams.put(FrameworkConstants.JSAttributes.JS_COMMON_OPTIONS, identifierParams);
        context.addAuthenticatorParams(contextParams);
    }

    private PushAuthContext getPushAuthContext(AuthenticationContext context) throws AuthenticationFailedException {

        if (context == null) {
            throw handleAuthErrorScenario(ERROR_CODE_AUTHENTICATION_CONTEXT_NOT_FOUND);
        }
        String pushAuthId = context.getProperty(PUSH_AUTH_ID).toString();
        if (StringUtils.isBlank(pushAuthId)) {
            throw handleAuthErrorScenario(ERROR_CODE_PUSH_AUTH_ID_NOT_FOUND);
        }
        PushAuthContext pushAuthContext = pushAuthContextManager.getContext(pushAuthId);
        if (pushAuthContext == null) {
            // Push Auth context is not found in cache. Hence, throwing an error.
            throw handleAuthErrorScenario(ERROR_CODE_PUSH_AUTH_CONTEXT_NOT_FOUND,
                    AuthenticatorUtils.maskIfRequired("username"));
        }
        return pushAuthContext;
    }

    private AdditionalData getAdditionalData(AuthenticationContext context, PushAuthContext pushAuthContext)
            throws AuthenticationFailedException {

        AdditionalData additionalData = new AdditionalData();
        Map<String, String> additionalParams = new HashMap<>();
        additionalParams.put("statusEndpoint", buildStatusCheckEndpoint(context, pushAuthContext));
        additionalData.setAdditionalAuthenticationParams(additionalParams);
        return additionalData;
    }

    private String buildStatusCheckEndpoint(AuthenticationContext context, PushAuthContext pushAuthContext)
            throws AuthenticationFailedException {

        String statusCheckEndpoint = null;
        String tenantDomain = context.getTenantDomain();
        String organizationId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getOrganizationId();
        String pushAuthId = context.getProperty(PUSH_AUTH_ID).toString();
        String statusCheckEndpointPath = "/push-auth/check-status?pushAuthId=" + pushAuthId;
        try {
            if (StringUtils.isNotBlank(organizationId)) {
                statusCheckEndpoint = ServiceURLBuilder.create().setOrganization(organizationId).
                        addPath(statusCheckEndpointPath).build().getAbsolutePublicURL();
            } else {
                statusCheckEndpoint = ServiceURLBuilder.create().setTenant(tenantDomain)
                        .addPath(statusCheckEndpointPath).build().getAbsolutePublicURL();
            }
        } catch (URLBuilderException e) {
            String error = "Error occurred while building the status check endpoint.";
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_BUILDING_STATUS_URL, error, e);
        }
        return statusCheckEndpoint;
    }

    /**
     * Handle the scenario by returning AuthenticationFailedException which has the details of the error scenario.
     *
     * @param error     {@link AuthenticatorConstants.ErrorMessages} error message.
     * @param throwable Throwable.
     * @param data      Additional data related to the scenario.
     * @return AuthenticationFailedException.
     */
    protected AuthenticationFailedException handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages error,
                                                                    Throwable throwable, Object... data) {

        String message = error.getMessage();
        if (data != null) {
            message = String.format(message, data);
        }
        String errorCode = error.getCode();
        if (throwable == null) {
            return new AuthenticationFailedException(errorCode, message);
        }
        return new AuthenticationFailedException(errorCode, message, throwable);
    }

    protected AuthenticationFailedException handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages error) {

        return handleAuthErrorScenario(error, null);
    }

    protected AuthenticationFailedException handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages error,
                                                                    Object... data) {

        return handleAuthErrorScenario(error, null, data);
    }

    protected AuthenticationFailedException handleAuthErrorScenario(String errorMsg, AuthenticationContext context,
                                                                    AuthenticatorConstants.ErrorMessages error,
                                                                    Object... data) {

        context.setProperty(SKIP_RETRY_FROM_AUTHENTICATOR, true);
        context.setProperty(AUTH_ERROR_MSG, errorMsg);
        return handleAuthErrorScenario(error, data);
    }

    /**
     * Resolve the scenario based on the request and the context.
     *
     * @param request           HttpServletRequest.
     * @param context           AuthenticationContext.
     */
    protected AuthenticatorConstants.ScenarioTypes resolveScenario(HttpServletRequest request,
                                                                             AuthenticationContext context) {

        if (context.isLogoutRequest()) {
            return LOGOUT;
        } else if (StringUtils.isNotBlank(request.getParameter(SCENARIO)) &&
                RESEND_PUSH_NOTIFICATION.getValue().equals(request.getParameter(SCENARIO))) {
            return RESEND_PUSH_NOTIFICATION;
        } else if (StringUtils.isNotBlank(request.getParameter(SCENARIO)) &&
                PROCEED_PUSH_AUTHENTICATION.getValue().equals(request.getParameter(SCENARIO))) {
            return PROCEED_PUSH_AUTHENTICATION;
        } else if (StringUtils.isNotBlank(request.getParameter(SCENARIO)) &&
                PUSH_DEVICE_ENROLLMENT.getValue().equals(request.getParameter(SCENARIO))) {
            return PUSH_DEVICE_ENROLLMENT;
        } else if (StringUtils.isNotBlank(request.getParameter(SCENARIO)) &&
                INIT_PUSH_ENROLL.getValue().equals(request.getParameter(SCENARIO))) {
            return INIT_PUSH_ENROLL;
        } else if (StringUtils.isNotBlank(request.getParameter(SCENARIO)) &&
                CANCEL_PUSH_ENROLL.getValue().equals(request.getParameter(SCENARIO))) {
            return CANCEL_PUSH_ENROLL;
        }
        return SEND_PUSH_NOTIFICATION;
    }

    /**
     * Get the number of maximum attempts the user is allowed resend the OTP.
     *
     * @return The maximum number of resend attempts.
     * @throws AuthenticationFailedException If an error occurs when retrieving config.
     */
    private int getMaximumResendAttempts(String tenantDomain) throws AuthenticationFailedException {

        try {
            return Integer.parseInt(AuthenticatorUtils.getPushAuthenticatorConfig(
                    RESEND_NOTIFICATION_MAX_ATTEMPTS, tenantDomain));
        } catch (PushAuthenticatorServerException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_CONFIG);
        }
    }

    /**
     * Get the authenticated user from the context.
     *
     * @param context Authentication context.
     * @return AuthenticatedUser.
     * @throws AuthenticationFailedException Authentication failed exception.
     */
    private AuthenticatedUser getAuthenticatedUserFromContext(AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        for (StepConfig stepConfig : stepConfigMap.values()) {
            AuthenticatedUser user = stepConfig.getAuthenticatedUser();
            if (stepConfig.isSubjectAttributeStep() && user != null) {
                if (StringUtils.isBlank(user.toFullQualifiedUsername())) {
                    LOG.debug("Username can not be empty.");
                    throw handleAuthErrorScenario(ERROR_CODE_NO_USER_FOUND);
                }
                return user;
            }
        }

        if (context.getLastAuthenticatedUser() != null
                && context.getLastAuthenticatedUser().getUserName() != null) {
            return context.getLastAuthenticatedUser();
        }

        StepConfig currentStep = stepConfigMap.get(context.getCurrentStep());
        if (currentStep.isSubjectAttributeStep()) {
            return null;
        }

        throw handleAuthErrorScenario(ERROR_CODE_NO_USER_FOUND);
    }

    /**
     * Check if the user is redirected from the identifier first UI.
     *
     * @param request   HttpServletRequest.
     * @return True if the user is redirected from the identifier first UI.
     */
    private boolean isUserRedirectedFromIDF(HttpServletRequest request) {

        return StringUtils.isNotBlank(request.getParameter(USERNAME))
                && StringUtils.isBlank(request.getParameter(PASSWORD));
    }

    /**
     * This method is used to redirect the user to the username entering page (IDF: Identifier first).
     *
     * @param request  Request.
     * @param response Response.
     * @param context  The authentication context.
     * @throws AuthenticationFailedException If an error occurred while setting redirect url.
     */
    private void redirectUserToIDF(HttpServletRequest request, HttpServletResponse response,
                                   AuthenticationContext context) throws AuthenticationFailedException {

        StringBuilder redirectUrl = new StringBuilder();
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        redirectUrl.append(loginPage);
        redirectUrl.append("?");

        String queryParams = context.getContextIdIncludedQueryParams();
        String multiOptionURI = AuthenticatorUtils.getMultiOptionURIQueryString(request);
        try {
            LOG.debug("Redirecting to identifier first flow since no authenticated user was found");
            if (queryParams != null) {
                redirectUrl.append(queryParams);
                redirectUrl.append("&");
            }
            redirectUrl.append(AUTHENTICATORS);
            redirectUrl.append(IDF_HANDLER_NAME);
            redirectUrl.append(":");
            redirectUrl.append(LOCAL_AUTHENTICATOR);
            redirectUrl.append(multiOptionURI);
            response.sendRedirect(redirectUrl.toString());
        } catch (IOException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_REDIRECTING_TO_IDF_PAGE);
        }
    }

    /**
     * This method is used to resolve the user from authentication request from identifier handler.
     *
     * @param request The httpServletRequest.
     * @param context The authentication context.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    private AuthenticatedUser resolveUserFromRequest(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        String identifierFromRequest = request.getParameter(USERNAME);
        if (StringUtils.isBlank(identifierFromRequest)) {
            throw handleAuthErrorScenario(ERROR_CODE_EMPTY_USERNAME);
        }
        String username = FrameworkUtils.preprocessUsername(identifierFromRequest, context);
        AuthenticatedUser user = new AuthenticatedUser();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        String tenantDomain = MultitenantUtils.getTenantDomain(username);

        user.setAuthenticatedSubjectIdentifier(tenantAwareUsername);
        user.setUserName(tenantAwareUsername);
        user.setUserStoreDomain(userStoreDomain);
        user.setTenantDomain(tenantDomain);
        return user;
    }

    /**
     * This method is used to resolve an authenticated user from the user stores.
     *
     * @param authenticatedUser The authenticated user.
     * @return Authenticated user retrieved from the user store.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    private AuthenticatedUser resolveUserFromUserStore(AuthenticatedUser authenticatedUser,
                                                       AuthenticationContext context)
            throws AuthenticationFailedException {

        User user = getUser(authenticatedUser, context);
        if (user == null) {
            return null;
        }
        authenticatedUser = new AuthenticatedUser(user);
        authenticatedUser.setAuthenticatedSubjectIdentifier(user.getUsername());
        return authenticatedUser;
    }

    /**
     * This method is used to set the resolved user in context.
     *
     * @param context           The authentication context.
     * @param authenticatedUser The authenticated user.
     */
    private void setResolvedUserInContext(AuthenticationContext context, AuthenticatedUser authenticatedUser) {

        if (authenticatedUser != null) {
            Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
            StepConfig currentStepConfig = stepConfigMap.get(context.getCurrentStep());
            if (currentStepConfig.isSubjectAttributeStep()) {
                context.setSubject(authenticatedUser);
                currentStepConfig.setAuthenticatedUser(authenticatedUser);
                currentStepConfig.setAuthenticatedIdP(LOCAL_AUTHENTICATOR);
            }
        }
    }

    /**
     * This method checks if all the authentication steps up to now have been performed by authenticators that
     * implements AuthenticationFlowHandler interface. If so, it returns true.
     * AuthenticationFlowHandlers may not perform actual authentication though the authenticated user is set in the
     * context. Hence, this method can be used to determine if the user has been authenticated by a previous step.
     *
     * @param context   AuthenticationContext.
     * @return True if all the authentication steps up to now have been performed by AuthenticationFlowHandlers.
     */
    private boolean isPreviousIdPAuthenticationFlowHandler(AuthenticationContext context) {

        Map<String, AuthenticatedIdPData> currentAuthenticatedIdPs = context.getCurrentAuthenticatedIdPs();
        return currentAuthenticatedIdPs != null && !currentAuthenticatedIdPs.isEmpty() &&
                currentAuthenticatedIdPs.values().stream().filter(Objects::nonNull)
                        .map(AuthenticatedIdPData::getAuthenticators).filter(Objects::nonNull)
                        .flatMap(List::stream)
                        .allMatch(authenticator ->
                                authenticator.getApplicationAuthenticator() instanceof AuthenticationFlowHandler);
    }

    /**
     * To redirect the flow to push notification wait page.
     *
     * @param response      HttpServletResponse.
     * @param pushId        Push ID.
     * @throws AuthenticationFailedException If an error occurred while redirecting to push auth wait page.
     */
    private void redirectToPushAuthWaitPage(AuthenticatedUser authenticatedUser, HttpServletResponse response,
                                              HttpServletRequest request, AuthenticationContext context, String pushId,
                                              String numberChallenge)
            throws AuthenticationFailedException {

        try {
            StringBuilder queryParamsBuilder = buildQueryParamsForPushWaitPage(authenticatedUser,
                    request, context, pushId, numberChallenge);
            String pushAuthWaitPageUrl = getPushAuthWaitPageUrl();
            String url = FrameworkUtils.appendQueryParamsStringToUrl(pushAuthWaitPageUrl,
                    queryParamsBuilder.toString());
            response.sendRedirect(url);
        } catch (IOException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_REDIRECTING_TO_LOGIN_PAGE, e, null);
        }
    }

    /**
     * Build query params for the push wait page.
     *
     * @param authenticatedUser Authenticated user.
     * @param request           HttpServletRequest.
     * @param context           AuthenticationContext.
     * @param pushId            Push ID.
     * @return Query params for the push wait page.
     * @throws AuthenticationFailedException If an error occurred while building query params.
     */
    protected StringBuilder buildQueryParamsForPushWaitPage(AuthenticatedUser authenticatedUser,
                                                            HttpServletRequest request, AuthenticationContext context,
                                                            String pushId, String numberChallenge)
            throws AuthenticationFailedException {

        String username = authenticatedUser.getUserName();
        StringBuilder queryParamsBuilder = new StringBuilder();
        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        String multiOptionURI = AuthenticatorUtils.getMultiOptionURIQueryString(request);
        queryParamsBuilder.append(queryParams)
                .append(AUTHENTICATORS_QUERY_PARAM).append(getName())
                .append(USERNAME_PARAM).append(username)
                .append(PUSH_AUTH_ID_PARAM).append(pushId)
                .append(multiOptionURI);

        if (isNumberChallengeEnabled(context.getTenantDomain())) {
            queryParamsBuilder.append(NUMBER_CHALLENGE_PARAM).append(numberChallenge);
        }

        boolean isResend = StringUtils.isNotBlank(request.getParameter(SCENARIO)) &&
                RESEND_PUSH_NOTIFICATION.getValue().equals(request.getParameter(SCENARIO));
        if (context.isRetrying() && !isResend) {
            queryParamsBuilder.append(RETRY_QUERY_PARAMS);
        }

        return queryParamsBuilder;
    }

    /**
     * Redirect the user to the device registration page.
     *
     * @param authenticatedUser Authenticated user.
     * @param response          HttpServletResponse.
     * @param request           HttpServletRequest.
     * @param context           AuthenticationContext.
     */
    private void redirectToRegistrationPage(AuthenticatedUser authenticatedUser, HttpServletResponse response,
                                              HttpServletRequest request, AuthenticationContext context,
                                              String enrollData)
            throws AuthenticationFailedException {

        try {
            StringBuilder queryParamsBuilder = buildQueryParamsForRegistrationPage(authenticatedUser, request, context,
                    enrollData);
            String pushDeviceRegistrationPageUrl = getRegistrationPageUrl();
            String url = FrameworkUtils.appendQueryParamsStringToUrl(pushDeviceRegistrationPageUrl,
                    queryParamsBuilder.toString());
            response.sendRedirect(url);
        } catch (IOException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_REDIRECTING_TO_DEVICE_REGISTRATION_PAGE, e, null);
        }
    }

    /**
     * Build query params for the device registration page.
     *
     * @param authenticatedUser Authenticated user.
     * @param request           HttpServletRequest.
     * @param context           AuthenticationContext.
     * @param enrollData        Enroll data.
     * @return Query params for the device registration page.
     */
    protected StringBuilder buildQueryParamsForRegistrationPage(AuthenticatedUser authenticatedUser,
                                                                HttpServletRequest request,
                                                                AuthenticationContext context,
                                                                String enrollData) {

        StringBuilder queryParamsBuilder = new StringBuilder();
        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        String multiOptionURI = AuthenticatorUtils.getMultiOptionURIQueryString(request);
        queryParamsBuilder.append(queryParams)
                .append(AUTHENTICATORS_QUERY_PARAM).append(getName())
                .append(USERNAME_PARAM).append(authenticatedUser.getUserName())
                .append(multiOptionURI)
                .append(ENROLL_DATA_PARAM).append(enrollData);
        return queryParamsBuilder;
    }

    /**
     * Handle the scenario when no device is found for the user and progressive device enrollment is enabled.
     *
     * @param request  HttpServletRequest.
     * @param response HttpServletResponse.
     * @param context  AuthenticationContext.
     */
    private void handleIDFUserDeviceEnrolEngageScenario(AuthenticatedUser authenticatedUser,
                                                        HttpServletResponse response, HttpServletRequest request,
                                                        AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            StringBuilder queryParamsBuilder =  buildQueryParamsForIDFUserDeviceEnrolConsentPage(authenticatedUser,
                    request, context);
            String pushDeviceRegistrationPageUrl = getPushDeviceEnrollConsentPageUrl();
            String url = FrameworkUtils.appendQueryParamsStringToUrl(pushDeviceRegistrationPageUrl,
                    queryParamsBuilder.toString());
            response.sendRedirect(url);
        } catch (IOException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_REDIRECTING_TO_DEVICE_REGISTRATION_PAGE, e, null);
        }
    }

    /**
     * Build query params for the IDF user device enrollment consent page.
     *
     * @param authenticatedUser Authenticated user.
     * @param request           HttpServletRequest.
     * @param context           AuthenticationContext.
     * @return Query params for the IDF user device enrollment consent page.
     */
    private StringBuilder buildQueryParamsForIDFUserDeviceEnrolConsentPage(AuthenticatedUser authenticatedUser,
                                                                            HttpServletRequest request,
                                                                            AuthenticationContext context) {

        StringBuilder queryParamsBuilder = new StringBuilder();
        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        String multiOptionURI = AuthenticatorUtils.getMultiOptionURIQueryString(request);
        queryParamsBuilder.append(queryParams)
                .append(AUTHENTICATORS_QUERY_PARAM).append(getName())
                .append(USERNAME_PARAM).append(authenticatedUser.getUserName())
                .append(multiOptionURI);
        return queryParamsBuilder;
    }

    /**
     * Retrieve the provisioned username of the authenticated user. If this is a federated scenario, the
     * authenticated username will be same as the username in context. If the flow is for a JIT provisioned user, the
     * provisioned username will be returned.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @param context           AuthenticationContext.
     * @return Provisioned username
     * @throws AuthenticationFailedException If an error occurred while getting the provisioned username.
     */
    private String getMappedLocalUsername(AuthenticatedUser authenticatedUser, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (!authenticatedUser.isFederatedUser()) {
            return authenticatedUser.getUserName();
        }
        // If the user is federated, we need to check whether the user is already provisioned to the organization.
        String federatedUsername = FederatedAuthenticatorUtil.getLoggedInFederatedUser(context);
        if (StringUtils.isBlank(federatedUsername)) {
            return StringUtils.EMPTY;
        }
        String associatedLocalUsername =
                FederatedAuthenticatorUtil.getLocalUsernameAssociatedWithFederatedUser(MultitenantUtils.
                        getTenantAwareUsername(federatedUsername), context);
        if (StringUtils.isNotBlank(associatedLocalUsername)) {
            return associatedLocalUsername;
        }
        return null;
    }

    /**
     * Identify the AuthenticatedUser that the authenticator trying to authenticate. This needs to be done to
     * identify the locally mapped user for federated authentication scenarios.
     *
     * @param authenticatedUserInContext AuthenticatedUser retrieved from context.
     * @param mappedLocalUsername        Mapped local username if available.
     * @param tenantDomain               Application tenant domain.
     * @param isInitialFederationAttempt Whether auth attempt by a not JIT provisioned federated user.
     * @return AuthenticatedUser that the authenticator trying to authenticate.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private AuthenticatedUser resolveAuthenticatingUser(AuthenticatedUser authenticatedUserInContext,
                                                        String mappedLocalUsername,
                                                        String tenantDomain, boolean isInitialFederationAttempt)
            throws AuthenticationFailedException {

        // This is a federated initial authentication scenario.
        if (isInitialFederationAttempt) {
            return authenticatedUserInContext;
        }
        // Handle local users.
        if (!authenticatedUserInContext.isFederatedUser()) {
            return authenticatedUserInContext;
        }
        /*
         * At this point, the authenticating user is in our system but has a different mapped username compared to the
         * identifier that is in the authentication context. Therefore, we need to have a new AuthenticatedUser object
         * with the mapped local username to identify the user.
         */
        AuthenticatedUser authenticatingUser = new AuthenticatedUser(authenticatedUserInContext);
        authenticatingUser.setUserName(mappedLocalUsername);
        authenticatingUser.setUserStoreDomain(getFederatedUserStoreDomain(authenticatedUserInContext, tenantDomain));
        return authenticatingUser;
    }

    /**
     * Get the JIT provisioning user store domain of the authenticated user.
     *
     * @param user         AuthenticatedUser.
     * @param tenantDomain Tenant domain.
     * @return JIT provisioning user store domain.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private String getFederatedUserStoreDomain(AuthenticatedUser user, String tenantDomain)
            throws AuthenticationFailedException {

        String federatedIdp = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(federatedIdp, tenantDomain);
        JustInTimeProvisioningConfig provisioningConfig = idp.getJustInTimeProvisioningConfig();
        if (provisioningConfig == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("No JIT provisioning configs for idp: %s in tenant: %s", federatedIdp,
                        tenantDomain));
            }
            return null;
        }
        String provisionedUserStore = provisioningConfig.getProvisioningUserStore();
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Setting user store: %s as the provisioning user store for user: %s in tenant: %s",
                    provisionedUserStore, user.getUserName(), tenantDomain));
        }
        return provisionedUserStore;
    }

    /**
     * Get the IdentityProvider by name.
     *
     * @param idpName      Identity Provider name.
     * @param tenantDomain Tenant domain.
     * @return IdentityProvider.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private IdentityProvider getIdentityProvider(String idpName, String tenantDomain) throws
            AuthenticationFailedException {

        try {
            IdentityProvider idp = AuthenticatorDataHolder.getInstance()
                    .getIdpManager().getIdPByName(idpName, tenantDomain);
            if (idp == null) {
                throw handleAuthErrorScenario(ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR, idpName, tenantDomain);
            }
            return idp;
        } catch (IdentityProviderManagementException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_FEDERATED_AUTHENTICATOR, idpName, tenantDomain);
        }
    }

    /**
     * Get user claim value.
     *
     * @param claimUri          Claim uri.
     * @param authenticatedUser AuthenticatedUser.
     * @param error             Error associated with the claim retrieval.
     * @return User claim value.
     * @throws AuthenticationFailedException If an error occurred while getting the claim value.
     */
    private String getUserClaimValueFromUserStore(String claimUri, AuthenticatedUser authenticatedUser,
                                                    AuthenticatorConstants.ErrorMessages error)
            throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
        try {
            Map<String, String> claimValues =
                    userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                            authenticatedUser.toFullQualifiedUsername()), new String[]{claimUri}, null);
            return claimValues.get(claimUri);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(error, e, AuthenticatorUtils.maskIfRequired(authenticatedUser.getUserName()));
        }
    }

    /**
     * Get UserStoreManager for the given user.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return UserStoreManager.
     * @throws AuthenticationFailedException If an error occurred while getting the UserStoreManager.
     */
    private UserStoreManager getUserStoreManager(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {

        UserRealm userRealm = getTenantUserRealm(authenticatedUser.getTenantDomain());
        String username = MultitenantUtils.getTenantAwareUsername(authenticatedUser.toFullQualifiedUsername());
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        try {
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager == null) {
                throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER, username);
            }
            if (StringUtils.isBlank(userStoreDomain) || PRIMARY_DEFAULT_DOMAIN_NAME.equals(userStoreDomain)) {
                return userStoreManager;
            }
            return ((AbstractUserStoreManager) userStoreManager).getSecondaryUserStoreManager(userStoreDomain);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER, e,
                    AuthenticatorUtils.maskIfRequired(username));
        }
    }

    /**
     * Get the UserRealm for the user given user.
     *
     * @param tenantDomain Tenant domain.
     * @return UserRealm.
     * @throws AuthenticationFailedException If an error occurred while getting the UserRealm.
     */
    private UserRealm getTenantUserRealm(String tenantDomain) throws AuthenticationFailedException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserRealm userRealm;
        try {
            userRealm = (AuthenticatorDataHolder.getInstance().getRealmService()).getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_USER_REALM, e, tenantDomain);
        }
        if (userRealm == null) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_USER_REALM, tenantDomain);
        }
        return userRealm;
    }

    /**
     * To redirect flow to error page with specific condition.
     *
     * @param response    The httpServletResponse.
     * @param context     The AuthenticationContext.
     * @param queryParams The query params.
     * @param retryParam  The retry param.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void redirectToErrorPage(HttpServletRequest request, HttpServletResponse response,
                                     AuthenticationContext context, String queryParams, String retryParam)
            throws AuthenticationFailedException {

        try {
            String multiOptionURIQueryString = AuthenticatorUtils.getMultiOptionURIQueryString(request);
            String queryString = queryParams + AUTHENTICATORS_QUERY_PARAM + getName() +
                    USERNAME_PARAM + context.getLastAuthenticatedUser().getUserName() + retryParam
                    + multiOptionURIQueryString;
            String errorPageUrl = getPushAuthPErrorPageUrl();
            String url = FrameworkUtils.appendQueryParamsStringToUrl(errorPageUrl, queryString);
            response.sendRedirect(url);
        } catch (IOException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE, e, null);
        }
    }

    /**
     * Handle scenario for account locked users.
     *
     * @param authenticatedUser Authenticated user provisioned in the server.
     * @param response          HttpServletResponse.
     * @param context           AuthenticationContext.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void handleScenarioForLockedUser(AuthenticatedUser authenticatedUser, HttpServletRequest request,
                                             HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        // By default, we are showing the authentication failure reason here.
        long unlockTime = getUnlockTimeInMilliSeconds(authenticatedUser);
        long timeToUnlock = unlockTime - System.currentTimeMillis();
        if (timeToUnlock > 0) {
            queryParams += UNLOCK_QUERY_PARAM + Math.round((double) timeToUnlock / 1000 / 60);
        }
        redirectToErrorPage(request, response, context, queryParams, ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS);
    }

    /**
     * Get user account unlock time in milliseconds. If no value configured for unlock time user claim, return 0.
     *
     * @param authenticatedUser The authenticated user.
     * @return User account unlock time in milliseconds. If no value is configured return 0.
     * @throws AuthenticationFailedException If an error occurred while getting the user unlock time.
     */
    private long getUnlockTimeInMilliSeconds(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        String username = authenticatedUser.toFullQualifiedUsername();
        String accountLockedTime = getUserClaimValueFromUserStore(ACCOUNT_UNLOCK_TIME_CLAIM, authenticatedUser,
                ERROR_CODE_ERROR_GETTING_ACCOUNT_UNLOCK_TIME);
        if (StringUtils.isBlank(accountLockedTime)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("No value configured for claim: %s for user: %s", ACCOUNT_UNLOCK_TIME_CLAIM,
                        username));
            }
            return 0;
        }
        return Long.parseLong(accountLockedTime);
    }

    /**
     * Handle the scenario where the push authentication failed.
     *
     * @param request  HttpServletRequest.
     * @param response HttpServletResponse.
     * @param context  AuthenticationContext.
     * @throws AuthenticationFailedException If an error occurred.
     */
    protected void handlePushAuthFailedScenario(HttpServletRequest request, HttpServletResponse response,
                                                       AuthenticationContext context, String errorParams)
            throws AuthenticationFailedException {

        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        redirectToErrorPage(request, response, context, queryParams, errorParams);
    }

    /**
     * Handle the scenario where the push notification sending failure.
     *
     * @param request  HttpServletRequest.
     * @param response HttpServletResponse.
     * @param context  AuthenticationContext.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void handleNotificationEventFailureScenario(HttpServletRequest request, HttpServletResponse response,
                                                        AuthenticationContext context)
            throws AuthenticationFailedException {

        // This logic has to be later improved to identify each error scenarios and show the user
        // a proper error message.
        handlePushAuthFailedScenario(request, response, context, ERROR_PUSH_INTERNAL_ERROR_QUERY_PARAMS);
    }

    /**
     * Initialize or increment the number of times the notification was resent to the user.
     *
     * @param context   Authentication Context.
     */
    private void updateResendCount(AuthenticationContext context) {

        if (context.getProperty(NOTIFICATION_RESEND_ATTEMPTS) == null ||
                StringUtils.isBlank(context.getProperty(NOTIFICATION_RESEND_ATTEMPTS).toString())) {
            context.setProperty(NOTIFICATION_RESEND_ATTEMPTS, 1);
        } else {
            context.setProperty(NOTIFICATION_RESEND_ATTEMPTS,
                    (int) context.getProperty(NOTIFICATION_RESEND_ATTEMPTS) + 1);
        }
    }

    /**
     * Prepare the challenges related to push authentication.
     *
     * @param pushAuthContext PushAuthContext.
     * @param tenantDomain    Tenant domain.
     * @throws AuthenticationFailedException If an error occurred while preparing the challenges.
     */
    private void prepareAuthChallenges(PushAuthContext pushAuthContext, String tenantDomain)
            throws AuthenticationFailedException {

        String challenge = UUID.randomUUID().toString();
        pushAuthContext.setChallenge(challenge);
        if (isNumberChallengeEnabled(tenantDomain)) {
            Random random = new Random();
            int numberChallenge = random.nextInt(100);
            pushAuthContext.setNumberChallenge(Integer.toString(numberChallenge));
        }
    }

    /**
     * Set the authenticator message to the context.
     *
     * @param context AuthenticationContext.
     */
    private static void setAuthenticatorMessage(AuthenticationContext context) {

        String message = "The code is successfully sent to the user's registered device";
        AuthenticatorMessage authenticatorMessage = new AuthenticatorMessage(FrameworkConstants.
                AuthenticatorMessageType.INFO, PUSH_NOTIFICATION_SENT, message, null);
        context.setProperty(AUTHENTICATOR_MESSAGE, authenticatorMessage);
    }

    /**
     * Trigger the push notification event.
     *
     * @param context           AuthenticationContext.
     * @param authenticatedUser AuthenticatedUser.
     * @param device            Device.
     * @param pushAuthContext   PushAuthContext.
     * @param request           HttpServletRequest.
     * @throws IdentityEventException If an error occurred while triggering the event.
     */
    private void triggerNotificationEvent(AuthenticationContext context, AuthenticatedUser authenticatedUser,
                                          Device device, PushAuthContext pushAuthContext, HttpServletRequest request)
            throws IdentityEventException {

        Map<String, Object> metaProperties = new HashMap<>();

        metaProperties.put(IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL,
                PUSH_NOTIFICATION_CHANNEL);
        metaProperties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME,
                context.getServiceProviderName());
        String authScenario = AuthenticatorConstants.NotificationScenarioTypes.PUSH_AUTHENTICATION.getValue();
        metaProperties.put(NOTIFICATION_SCENARIO, authScenario);

        metaProperties.put(PUSH_ID, context.getProperty(PUSH_AUTH_ID));
        metaProperties.put(DEVICE_TOKEN, device.getDeviceToken());
        metaProperties.put(NOTIFICATION_PROVIDER, device.getProvider());
        metaProperties.put(DEVICE_ID, device.getDeviceId());

        metaProperties.put(CHALLENGE, pushAuthContext.getChallenge());
        metaProperties.put(NUMBER_CHALLENGE, pushAuthContext.getNumberChallenge());

        String hostname = request.getRemoteAddr();
        metaProperties.put(IP_ADDRESS, hostname);

        Client client = getClient(request);
        if (client != null) {
            String userOS = client.os.family;
            String userBrowser = client.userAgent.family;
            metaProperties.put(REQUEST_DEVICE_OS, userOS);
            metaProperties.put(REQUEST_DEVICE_BROWSER, userBrowser);
        }

        setAuthenticatorMessage(context);

        /* SaaS apps are created at the super tenant level and they can be accessed by users of other organizations.
        If users of other organizations try to login to a saas app, the push notification should be triggered from the
        push provider configured for that organization. Hence, we need to start a new tenanted flow here. */
        if (context.getSequenceConfig().getApplicationConfig().isSaaSApp()) {
            try {
                FrameworkUtils.startTenantFlow(authenticatedUser.getTenantDomain());
                triggerEvent(PUSH_NOTIFICATION_EVENT_NAME, authenticatedUser, metaProperties);
            } finally {
                FrameworkUtils.endTenantFlow();
            }
        } else {
            triggerEvent(PUSH_NOTIFICATION_EVENT_NAME, authenticatedUser, metaProperties);
        }

    }

    /**
     * Trigger identity event.
     *
     * @param eventName      Event name.
     * @param user           Authenticated user.
     * @param eventProperties Meta details.
     * @throws IdentityEventException If an error occurred while triggering the event.
     */
    protected void triggerEvent(String eventName, AuthenticatedUser user,
                                Map<String, Object> eventProperties) throws IdentityEventException {

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUserName());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(TENANT_DOMAIN, user.getTenantDomain());
        if (eventProperties != null) {
            for (Map.Entry<String, Object> metaProperty : eventProperties.entrySet()) {
                if (StringUtils.isNotBlank(metaProperty.getKey()) && metaProperty.getValue() != null) {
                    properties.put(metaProperty.getKey(), metaProperty.getValue());
                }
            }
        }
        Event identityMgtEvent = new Event(eventName, properties);
        AuthenticatorDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
    }

    /**
     * Get the client properties using the user-agent request header.
     *
     * @param request HTTP request
     * @return UA Client
     */
    protected Client getClient(HttpServletRequest request) {

        String userAgentString = request.getHeader(USER_AGENT);
        try {
            Parser uaParser = new Parser();
            return uaParser.parse(userAgentString);
        } catch (IOException e) {
            // If exception occurs, log and continue the flow without throwing the exception.
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error occurred while parsing the user agent string.", e);
            }
            return null;
        }
    }

    /**
     * Check whether the progressive device enrollment is enabled for the tenant.
     *
     * @param tenantDomain Tenant domain.
     * @return True if the progressive device enrollment is enabled.
     * @throws AuthenticationFailedException If an error occurred while checking the configuration.
     */
    protected boolean isProgressiveDeviceEnrollmentEnabled(String tenantDomain) throws AuthenticationFailedException {

        try {
            return Boolean.parseBoolean(
                    AuthenticatorUtils.getPushAuthenticatorConfig(
                            ENABLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT, tenantDomain));
        } catch (PushAuthenticatorServerException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_CONFIG);
        }
    }

    /**
     * Check whether the number challenge is enabled for the tenant.
     *
     * @param tenantDomain Tenant domain.
     * @return True if the number challenge is enabled.
     * @throws AuthenticationFailedException If an error occurred while checking the configuration.
     */
    protected boolean isNumberChallengeEnabled(String tenantDomain) throws AuthenticationFailedException {

        try {
            return Boolean.parseBoolean(
                    AuthenticatorUtils.getPushAuthenticatorConfig(
                            ENABLE_PUSH_NUMBER_CHALLENGE, tenantDomain));
        } catch (PushAuthenticatorServerException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_CONFIG);
        }
    }

    /**
     * Reset Auth Failed Attempts count upon successful completion of the push notification verification.
     *
     * @param user AuthenticatedUser.
     * @param isInitialFederationAttempt is initial federation attempt.
     * @throws AuthenticationFailedException If an error occurred while resetting the OTP failed attempts.
     */
    protected void resetAuthFailedAttempts(AuthenticatedUser user, boolean isInitialFederationAttempt)
            throws AuthenticationFailedException {

        // A mapped user is not available for isInitialFederationAttempt true scenario. Hence, no need to handle.
        if (isInitialFederationAttempt) {
            return;
        }

        UserStoreManager userStoreManager = getUserStoreManager(user);
        // Add required meta properties to the event.
        Map<String, Object> metaProperties = new HashMap<>();
        metaProperties.put(AUTHENTICATOR_NAME, getName());
        metaProperties.put(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM, PUSH_AUTH_FAILED_ATTEMPTS_CLAIM);
        metaProperties.put(USER_STORE_MANAGER, userStoreManager);
        metaProperties.put(OPERATION_STATUS, true);

        try {
            triggerEvent(POST_NON_BASIC_AUTHENTICATION, user, metaProperties);
        } catch (IdentityEventException e) {
            throw new AuthenticationFailedException("Error while resetting the OTP failed attempts.", e);
        }
    }

    /**
     * Execute account lock flow for push notification verification failures. By default, the push
     * authenticator will support account lock on failed attempts if the account locking is enabled for the tenant.
     *
     * @param user AuthenticatedUser.
     * @param isInitialFederationAttempt is initial federation attempt.
     * @throws AuthenticationFailedException If an error occurred while resetting the OTP failed attempts.
     */
    protected void handlePushAuthVerificationFail(AuthenticatedUser user, boolean isInitialFederationAttempt)
            throws AuthenticationFailedException {

        // A mapped user is not available for isInitialFederationAttempt true scenario. Hence, no need to handle.
        if (isInitialFederationAttempt) {
            return;
        }

        UserStoreManager userStoreManager = getUserStoreManager(user);
        // Add required meta properties to the event.
        Map<String, Object> metaProperties = new HashMap<>();
        metaProperties.put(AUTHENTICATOR_NAME, getName());
        metaProperties.put(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM, PUSH_AUTH_FAILED_ATTEMPTS_CLAIM);
        metaProperties.put(USER_STORE_MANAGER, userStoreManager);
        metaProperties.put(OPERATION_STATUS, false);

        try {
            triggerEvent(POST_NON_BASIC_AUTHENTICATION, user, metaProperties);

        } catch (IdentityEventException e) {
            throw new AuthenticationFailedException("Error while handling push auth verification failure.", e);
        }
    }

}
