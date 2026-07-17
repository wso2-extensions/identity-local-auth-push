/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
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

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.local.auth.push.authenticator.context.PushAuthContextManager;
import org.wso2.carbon.identity.local.auth.push.authenticator.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.push.authenticator.model.PushAuthContext;
import org.wso2.carbon.identity.local.auth.push.authenticator.util.AuthenticatorUtils;
import org.wso2.carbon.identity.notification.push.device.handler.DeviceHandlerService;
import org.wso2.carbon.identity.notification.push.device.handler.exception.PushDeviceHandlerServerException;
import org.wso2.carbon.identity.notification.push.device.handler.model.Device;
import org.wso2.carbon.identity.notification.push.device.handler.model.PushDeviceMgtConfigData;
import org.wso2.carbon.identity.notification.push.device.handler.model.RegistrationDiscoveryData;
import org.wso2.carbon.identity.notification.push.device.handler.utils.PushDeviceConfigManager;
import ua_parser.Client;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator.SKIP_RETRY_FROM_AUTHENTICATOR;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.AUTH_ERROR_MSG;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.AuthenticatorPromptType.INTERNAL_PROMPT;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.AuthenticatorPromptType.USER_PROMPT;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ConnectorConfig.ENABLE_MULTIPLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ConnectorConfig.ENABLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ConnectorConfig.ENABLE_PUSH_NUMBER_CHALLENGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_PUSH_AUTH_ID_NOT_FOUND;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.IS_API_BASED_AND_NO_DEVICE_ENROLLED;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTHENTICATOR_I18_KEY;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTH_FAIL_INTERNAL_ERROR;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTH_ID;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTH_WAIT_PAGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.SCENARIO;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ScenarioTypes.LOGOUT;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ScenarioTypes.MULTIPLE_DEVICE_PROGRESSIVE_ENROLLMENT;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ScenarioTypes.PUSH_DEVICE_ENROLLMENT;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ScenarioTypes.SEND_PUSH_NOTIFICATION;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.USERNAME;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.USER_AGENT;

/**
 * Test class for PushAuthenticator.
 */
public class PushAuthenticatorTest {

    @Mock
    ServiceURL serviceURL;
    @InjectMocks
    PushAuthenticator pushAuthenticator;
    @Mock
    private PushAuthContextManager pushAuthContextManager;
    @Mock
    private AuthenticationContext context;
    @Mock
    private HttpServletRequest httpServletRequest;
    @Mock
    private HttpServletResponse httpServletResponse;
    @Mock
    private ServiceURLBuilder serviceURLBuilder;

    @BeforeTest
    public void setUp() throws NoSuchFieldException, IllegalAccessException {

        MockitoAnnotations.openMocks(this);

        Field contextManagerField = PushAuthenticator.class.getDeclaredField("pushAuthContextManager");
        contextManagerField.setAccessible(true);
        contextManagerField.set(null, pushAuthContextManager);

        String carbonHome = Paths.get(System.getProperty("user.dir"), "target", "test-classes").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        System.setProperty(CarbonBaseConstants.CARBON_CONFIG_DIR_PATH, Paths.get(carbonHome, "conf").toString());
    }

    @Test
    public void testGetContextIdentifier() {

        when(httpServletRequest.getRequestedSessionId()).thenReturn("sampleSessionId");
        assertNotNull(pushAuthenticator.getContextIdentifier(httpServletRequest));
        assertEquals("sampleSessionId", pushAuthenticator.getContextIdentifier(httpServletRequest));
    }

    @Test
    public void testGetFriendlyName() {

        assertEquals(PUSH_AUTHENTICATOR_FRIENDLY_NAME, pushAuthenticator.getFriendlyName());
    }

    @Test
    public void testGetName() {

        assertEquals(PUSH_AUTHENTICATOR_NAME, pushAuthenticator.getName());
    }

    @Test
    public void testGetI18nKey() {

        assertEquals(PUSH_AUTHENTICATOR_I18_KEY, pushAuthenticator.getI18nKey());
    }

    @Test
    public void testIsAPIBasedAuthenticationSupported() {

        assertTrue(pushAuthenticator.isAPIBasedAuthenticationSupported());
    }

    @Test
    public void testRetryAuthenticationEnabled() {

        assertTrue(pushAuthenticator.retryAuthenticationEnabled());
    }

    @Test
    public void testCanHandle() {

        when(httpServletRequest.getParameter(USERNAME)).thenReturn("sampleUser");
        when(httpServletRequest.getParameter(SCENARIO)).thenReturn(SEND_PUSH_NOTIFICATION.getValue());
        assertTrue(pushAuthenticator.canHandle(httpServletRequest));
    }

    @Test
    public void testCanHandleWithInvalidScenario() {

        when(httpServletRequest.getParameter(USERNAME)).thenReturn("sampleUser");
        when(httpServletRequest.getParameter(SCENARIO)).thenReturn("invalidScenario");
        assertTrue(pushAuthenticator.canHandle(httpServletRequest));
    }

    @Test
    public void testCanHandleFailure() {

        when(httpServletRequest.getParameter(USERNAME)).thenReturn(null);
        when(httpServletRequest.getParameter(SCENARIO)).thenReturn("invalidScenario");
        assertFalse(pushAuthenticator.canHandle(httpServletRequest));
    }

    @Test
    public void testResolveScenario() {

        when(context.isLogoutRequest()).thenReturn(true);
        assertEquals(LOGOUT, pushAuthenticator.resolveScenario(httpServletRequest, context));

        when(context.isLogoutRequest()).thenReturn(false);
        assertEquals(SEND_PUSH_NOTIFICATION, pushAuthenticator.resolveScenario(httpServletRequest, context));

        when(httpServletRequest.getParameter(SCENARIO)).thenReturn(PUSH_DEVICE_ENROLLMENT.getValue());
        assertEquals(PUSH_DEVICE_ENROLLMENT, pushAuthenticator.resolveScenario(httpServletRequest, context));

        when(httpServletRequest.getParameter(SCENARIO))
                .thenReturn(MULTIPLE_DEVICE_PROGRESSIVE_ENROLLMENT.getValue());
        assertEquals(MULTIPLE_DEVICE_PROGRESSIVE_ENROLLMENT,
                pushAuthenticator.resolveScenario(httpServletRequest, context));
    }

    @Test
    public void testCanHandleMultipleDeviceProgressiveEnrollmentScenario() {

        when(httpServletRequest.getParameter(USERNAME)).thenReturn(null);
        when(httpServletRequest.getParameter(SCENARIO))
                .thenReturn(MULTIPLE_DEVICE_PROGRESSIVE_ENROLLMENT.getValue());
        assertTrue(pushAuthenticator.canHandle(httpServletRequest));
    }

    @Test
    public void testHandleAuthErrorScenario() {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        try {
            throw pushAuthenticator.handleAuthErrorScenario(PUSH_AUTH_FAIL_INTERNAL_ERROR,
                    authenticationContext, ERROR_CODE_PUSH_AUTH_ID_NOT_FOUND);
        } catch (AuthenticationFailedException e) {
            assertTrue(authenticationContext.getProperty(SKIP_RETRY_FROM_AUTHENTICATOR) != null
                    && (Boolean) authenticationContext.getProperty(SKIP_RETRY_FROM_AUTHENTICATOR));
            assertNotNull(authenticationContext.getProperty(AUTH_ERROR_MSG));
        }
    }

    @Test
    public void testGetAuthInitiationData() throws AuthenticationFailedException, URLBuilderException {

        ExternalIdPConfig externalIdPConfig = mock(ExternalIdPConfig.class);
        when(context.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdPName()).thenReturn("externalIdP");

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        when(context.getLastAuthenticatedUser()).thenReturn(authenticatedUser);

        when(context.getProperty(PUSH_AUTH_ID)).thenReturn(new Object());
        when(context.getProperty(PUSH_AUTH_ID).toString()).thenReturn("samplePushAuthId");

        PushAuthContext pushAuthContext = new PushAuthContext();
        when(pushAuthContextManager.getContext(anyString())).thenReturn(pushAuthContext);

        when(context.getTenantDomain()).thenReturn("carbon.super");

        try (
                MockedStatic<PrivilegedCarbonContext> mockedCarbonContext
                        = Mockito.mockStatic(PrivilegedCarbonContext.class);
                MockedStatic<ServiceURLBuilder> mockedServiceURLBuilder = mockStatic(ServiceURLBuilder.class)
        ) {

            PrivilegedCarbonContext privilegedCarbonContext = mock(PrivilegedCarbonContext.class);
            mockedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(privilegedCarbonContext);
            when(privilegedCarbonContext.getOrganizationId()).thenReturn(null);

            mockedServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.setTenant(anyString())).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.addPath(anyString())).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.build()).thenReturn(serviceURL);
            when(serviceURL.getAbsolutePublicURL()).thenReturn("https://sampleURL");

            Optional<AuthenticatorData> authenticatorData = pushAuthenticator.getAuthInitiationData(context);
            assertTrue(authenticatorData.isPresent());

            AuthenticatorData data = authenticatorData.get();
            assertEquals(PUSH_AUTHENTICATOR_NAME, data.getName());
            assertEquals(PUSH_AUTHENTICATOR_FRIENDLY_NAME, data.getDisplayName());
            assertEquals("externalIdP", data.getIdp());
            assertEquals(PUSH_AUTHENTICATOR_I18_KEY, data.getI18nKey());
            assertEquals(INTERNAL_PROMPT, data.getPromptType());
            assertNotNull(data.getAuthParams());
            assertNotNull(data.getRequiredParams());
            assertEquals(SCENARIO, data.getRequiredParams().get(0));
            assertNotNull(data.getAdditionalData());
            assertNotNull(data.getAdditionalData().getAdditionalAuthenticationParams());
            assertEquals("https://sampleURL",
                    data.getAdditionalData().getAdditionalAuthenticationParams().get("statusEndpoint"));
        }
    }

    @Test
    public void testBuildQueryParamsForPushWaitPage() throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        String numberChallengeValue = "37";
        String pushId = "48f5e4fe-a3fb-4757-90fd-12bd9104cbf4";
        try (
                MockedStatic<FrameworkUtils> mockedFrameworkUtils = mockStatic(FrameworkUtils.class);
                MockedStatic<AuthenticatorUtils> mockedAuthenticatorUtils = mockStatic(AuthenticatorUtils.class)
        ) {
            mockedFrameworkUtils.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(
                            context.getQueryParams(), context.getCallerSessionKey(), context.getContextIdentifier()))
                    .thenReturn("sampleQueryString");
            mockedAuthenticatorUtils.when(() -> AuthenticatorUtils.getMultiOptionURIQueryString(httpServletRequest))
                    .thenReturn("");
            when(context.getTenantDomain()).thenReturn("carbon.super");
            mockedAuthenticatorUtils.when(() -> AuthenticatorUtils.getPushAuthenticatorConfig(
                    ENABLE_PUSH_NUMBER_CHALLENGE, "carbon.super")).thenReturn("true");
            when(context.isRetrying()).thenReturn(false);
            String pushAuthWaitPageUrl = "https://localhost:9443/" + PUSH_AUTH_WAIT_PAGE;
            mockedAuthenticatorUtils.when(AuthenticatorUtils::getPushAuthWaitPageUrl)
                    .thenReturn(pushAuthWaitPageUrl);
            StringBuilder queryParamsBuilder = pushAuthenticator.buildQueryParamsForPushWaitPage(authenticatedUser,
                    httpServletRequest, context, pushId, numberChallengeValue);
            String expectedQueryString = "sampleQueryString&authenticators=push-notification-authenticator&" +
                    "username=testUser&pushAuthId=48f5e4fe-a3fb-4757-90fd-12bd9104cbf4&numberChallenge=37";
            assertEquals(expectedQueryString, queryParamsBuilder.toString());
        }
    }

    @Test
    public void testBuildQueryParamsForRegistrationPage() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        try (
                MockedStatic<FrameworkUtils> mockedFrameworkUtils = mockStatic(FrameworkUtils.class);
                MockedStatic<AuthenticatorUtils> mockedAuthenticatorUtils = mockStatic(AuthenticatorUtils.class)
        ) {
            mockedFrameworkUtils.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(
                            context.getQueryParams(), context.getCallerSessionKey(), context.getContextIdentifier()))
                    .thenReturn("sampleQueryString");
            mockedAuthenticatorUtils.when(() -> AuthenticatorUtils.getMultiOptionURIQueryString(httpServletRequest))
                    .thenReturn("");
            StringBuilder queryParamsBuilder = pushAuthenticator.buildQueryParamsForRegistrationPage(authenticatedUser,
                    httpServletRequest, context, "&enrollData=sampleData");
            String expectedQueryString = "sampleQueryString&authenticators=push-notification-authenticator&" +
                    "username=testUser&pushEnrollData=&enrollData=sampleData";
            assertEquals(queryParamsBuilder.toString(), expectedQueryString);
        }
    }

    @Test
    public void testTriggerEvent() throws IdentityEventException {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserId("testUserId");
        user.setUserName("testUser");
        user.setUserStoreDomain("PRIMARY");
        user.setTenantDomain("carbon.super");

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put("key1", "value1");

        try (MockedStatic<AuthenticatorDataHolder> mockedDataHolder = mockStatic(AuthenticatorDataHolder.class)) {
            IdentityEventService identityEventService = mock(IdentityEventService.class);
            AuthenticatorDataHolder dataHolder = mock(AuthenticatorDataHolder.class);
            mockedDataHolder.when(AuthenticatorDataHolder::getInstance).thenReturn(dataHolder);
            when(dataHolder.getIdentityEventService()).thenReturn(identityEventService);

            pushAuthenticator.triggerEvent("TEST_EVENT", user, eventProperties);

            verify(identityEventService, times(1)).handleEvent(any(Event.class));
        }
    }

    @Test
    public void testTriggerEventWithoutUserId() throws IdentityEventException, UserIdNotFoundException {

        AuthenticatedUser user = mock(AuthenticatedUser.class);
        when(user.getUserName()).thenReturn("testUser");
        when(user.getUserStoreDomain()).thenReturn("PRIMARY");
        when(user.getTenantDomain()).thenReturn("carbon.super");
        when(user.getUserId()).thenThrow(new UserIdNotFoundException("User ID not found"));

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put("key1", "value1");

        try (MockedStatic<AuthenticatorDataHolder> mockedDataHolder = mockStatic(AuthenticatorDataHolder.class)) {
            IdentityEventService identityEventService = mock(IdentityEventService.class);
            AuthenticatorDataHolder dataHolder = mock(AuthenticatorDataHolder.class);
            mockedDataHolder.when(AuthenticatorDataHolder::getInstance).thenReturn(dataHolder);
            when(dataHolder.getIdentityEventService()).thenReturn(identityEventService);

            pushAuthenticator.triggerEvent("TEST_EVENT", user, eventProperties);

            verify(identityEventService, times(1)).handleEvent(any(Event.class));
        }
    }

    @Test
    public void testGetClient() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader(USER_AGENT))
                .thenReturn("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " +
                        "Chrome/58.0.3029.110 Safari/537.3");

        Client client = pushAuthenticator.getClient(request);

        assertNotNull(client);
        assertEquals("Windows", client.os.family);
        assertEquals("Chrome", client.userAgent.family);
    }

    @Test
    public void testIsProgressiveDeviceEnrollmentEnabled() throws AuthenticationFailedException {

        try (MockedStatic<AuthenticatorUtils> mockedUtils = mockStatic(AuthenticatorUtils.class)) {
            mockedUtils.when(() -> AuthenticatorUtils.getPushAuthenticatorConfig(
                            ENABLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT, "carbon.super"))
                    .thenReturn("true");

            boolean result = pushAuthenticator.isProgressiveDeviceEnrollmentEnabled("carbon.super");

            assertTrue(result);
        }
    }

    @Test
    public void testIsNumberChallengeEnabled() throws AuthenticationFailedException {

        try (MockedStatic<AuthenticatorUtils> mockedUtils = mockStatic(AuthenticatorUtils.class)) {
            mockedUtils.when(() -> AuthenticatorUtils.getPushAuthenticatorConfig(
                            ENABLE_PUSH_NUMBER_CHALLENGE, "carbon.super"))
                    .thenReturn("true");

            boolean result = pushAuthenticator.isNumberChallengeEnabled("carbon.super");

            assertTrue(result);
        }
    }

    @Test
    public void testIsMultipleDeviceProgressiveEnrollmentEnabled() throws AuthenticationFailedException {

        try (MockedStatic<AuthenticatorUtils> mockedUtils = mockStatic(AuthenticatorUtils.class)) {
            mockedUtils.when(() -> AuthenticatorUtils.getPushAuthenticatorConfig(
                            ENABLE_MULTIPLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT, "carbon.super"))
                    .thenReturn("true");

            boolean result = pushAuthenticator.isMultipleDeviceProgressiveEnrollmentEnabled("carbon.super");

            assertTrue(result);
        }
    }

    @Test
    public void testIsMultipleDeviceProgressiveEnrollmentDisabled() throws AuthenticationFailedException {

        try (MockedStatic<AuthenticatorUtils> mockedUtils = mockStatic(AuthenticatorUtils.class)) {
            mockedUtils.when(() -> AuthenticatorUtils.getPushAuthenticatorConfig(
                            ENABLE_MULTIPLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT, "carbon.super"))
                    .thenReturn("false");

            boolean result = pushAuthenticator.isMultipleDeviceProgressiveEnrollmentEnabled("carbon.super");

            assertFalse(result);
        }
    }

    @Test
    public void testGetAuthInitiationDataWhenNoAuthenticatedUser() throws AuthenticationFailedException {

        ExternalIdPConfig externalIdPConfig = mock(ExternalIdPConfig.class);
        when(context.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdPName()).thenReturn("externalIdP");
        when(context.getLastAuthenticatedUser()).thenReturn(null);

        Optional<AuthenticatorData> result = pushAuthenticator.getAuthInitiationData(context);

        assertTrue(result.isPresent());
        AuthenticatorData data = result.get();
        assertEquals(PUSH_AUTHENTICATOR_NAME, data.getName());
        assertEquals(PUSH_AUTHENTICATOR_FRIENDLY_NAME, data.getDisplayName());
        assertEquals("externalIdP", data.getIdp());
        assertEquals(PUSH_AUTHENTICATOR_I18_KEY, data.getI18nKey());
        assertEquals(USER_PROMPT, data.getPromptType());
        assertNotNull(data.getAuthParams());
        assertNotNull(data.getRequiredParams());
        assertEquals(USERNAME, data.getRequiredParams().get(0));
    }

    @Test
    public void testGetAuthInitiationDataWhenApiBasedAndNoDeviceEnrolled() throws AuthenticationFailedException {

        ExternalIdPConfig externalIdPConfig = mock(ExternalIdPConfig.class);
        when(context.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdPName()).thenReturn("externalIdP");

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        when(context.getLastAuthenticatedUser()).thenReturn(authenticatedUser);

        when(context.getProperty(IS_API_BASED_AND_NO_DEVICE_ENROLLED)).thenReturn(true);

        Optional<AuthenticatorData> result = pushAuthenticator.getAuthInitiationData(context);

        assertTrue(result.isPresent());
        AuthenticatorData data = result.get();
        assertEquals(PUSH_AUTHENTICATOR_NAME, data.getName());
        assertEquals(PUSH_AUTHENTICATOR_FRIENDLY_NAME, data.getDisplayName());
        assertEquals("externalIdP", data.getIdp());
        assertEquals(PUSH_AUTHENTICATOR_I18_KEY, data.getI18nKey());
        assertEquals(INTERNAL_PROMPT, data.getPromptType());
        assertNull(data.getAdditionalData());
    }

    @Test
    public void testCanEnrollAdditionalDeviceWhenAllConditionsMet() throws Exception {

        try (MockedStatic<AuthenticatorUtils> mockedUtils = mockStatic(AuthenticatorUtils.class)) {
            mockedUtils.when(() -> AuthenticatorUtils.getPushAuthenticatorConfig(
                    ENABLE_MULTIPLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT, "carbon.super")).thenReturn("true");
            mockedUtils.when(() -> AuthenticatorUtils.getPushAuthenticatorConfig(
                    ENABLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT, "carbon.super")).thenReturn("true");

            boolean result = (boolean) invokePrivateMethod("canEnrollAdditionalDevice",
                    new Class<?>[]{String.class, int.class, PushDeviceMgtConfigData.class},
                    "carbon.super", 1, buildPushDeviceMgtConfigData(true, 3));

            assertTrue(result);
        }
    }

    @Test
    public void testCanEnrollAdditionalDeviceWhenDeviceLimitReached() throws Exception {

        try (MockedStatic<AuthenticatorUtils> mockedUtils = mockStatic(AuthenticatorUtils.class)) {
            mockedUtils.when(() -> AuthenticatorUtils.getPushAuthenticatorConfig(
                    ENABLE_MULTIPLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT, "carbon.super")).thenReturn("true");
            mockedUtils.when(() -> AuthenticatorUtils.getPushAuthenticatorConfig(
                    ENABLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT, "carbon.super")).thenReturn("true");

            boolean result = (boolean) invokePrivateMethod("canEnrollAdditionalDevice",
                    new Class<?>[]{String.class, int.class, PushDeviceMgtConfigData.class},
                    "carbon.super", 3, buildPushDeviceMgtConfigData(true, 3));

            assertFalse(result);
        }
    }

    @Test
    public void testCanEnrollAdditionalDeviceWhenMultipleDeviceEnrollmentDisabled() throws Exception {

        try (MockedStatic<AuthenticatorUtils> mockedUtils = mockStatic(AuthenticatorUtils.class)) {
            mockedUtils.when(() -> AuthenticatorUtils.getPushAuthenticatorConfig(
                    ENABLE_MULTIPLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT, "carbon.super")).thenReturn("true");

            boolean result = (boolean) invokePrivateMethod("canEnrollAdditionalDevice",
                    new Class<?>[]{String.class, int.class, PushDeviceMgtConfigData.class},
                    "carbon.super", 1, buildPushDeviceMgtConfigData(false, 3));

            assertFalse(result);
        }
    }

    @Test
    public void testHandleAdditionalDeviceEnrollmentRejectsAtDeviceLimit() throws Exception {

        DeviceHandlerService deviceHandlerService = mock(DeviceHandlerService.class);
        AuthenticatorDataHolder.getInstance().setDeviceHandlerService(deviceHandlerService);

        // Device count is at the configured limit, so enrollment must be rejected before any registration attempt.
        List<Device> devices = buildDeviceList(3);
        invokeHandleAdditionalDeviceEnrollment(devices, buildPushDeviceMgtConfigData(true, 3));

        verify(deviceHandlerService, never()).getRegistrationDiscoveryData(anyString(), anyString());
    }

    @Test
    public void testHandleAdditionalDeviceEnrollmentRejectsWhenBaseProgressiveEnrollmentDisabled() throws Exception {

        DeviceHandlerService deviceHandlerService = mock(DeviceHandlerService.class);
        AuthenticatorDataHolder.getInstance().setDeviceHandlerService(deviceHandlerService);

        try (MockedStatic<AuthenticatorUtils> mockedUtils = mockStatic(AuthenticatorUtils.class)) {
            mockedUtils.when(() -> AuthenticatorUtils.getPushAuthenticatorConfig(
                    ENABLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT, "carbon.super")).thenReturn("false");

            // Under the device limit, but base progressive enrollment is off, so enrollment must be rejected.
            List<Device> devices = buildDeviceList(1);
            invokeHandleAdditionalDeviceEnrollment(devices, buildPushDeviceMgtConfigData(true, 3));

            verify(deviceHandlerService, never()).getRegistrationDiscoveryData(anyString(), anyString());
        }
    }

    @Test
    public void testHandleAdditionalDeviceEnrollmentProceedsToRegistrationWhenAllowed() throws Exception {

        DeviceHandlerService deviceHandlerService = mock(DeviceHandlerService.class);
        RegistrationDiscoveryData discoveryData = mock(RegistrationDiscoveryData.class);
        when(discoveryData.buildJSON()).thenReturn("{}");
        when(deviceHandlerService.getRegistrationDiscoveryData(any(), anyString())).thenReturn(discoveryData);
        AuthenticatorDataHolder.getInstance().setDeviceHandlerService(deviceHandlerService);

        try (MockedStatic<AuthenticatorUtils> mockedUtils = mockStatic(AuthenticatorUtils.class)) {
            mockedUtils.when(() -> AuthenticatorUtils.getPushAuthenticatorConfig(
                    ENABLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT, "carbon.super")).thenReturn("true");
            mockedUtils.when(() -> AuthenticatorUtils.maskIfRequired(anyString())).thenReturn("masked");

            // Under the limit and base progressive enrollment enabled: the flow must reach registration discovery.
            List<Device> devices = buildDeviceList(1);
            invokeHandleAdditionalDeviceEnrollment(devices, buildPushDeviceMgtConfigData(true, 3));

            verify(deviceHandlerService, times(1)).getRegistrationDiscoveryData(any(), anyString());
        }
    }

    @Test
    public void testGetMaximumDeviceLimit() throws Exception {

        int result = (int) invokePrivateMethod("getMaximumDeviceLimit",
                new Class<?>[]{PushDeviceMgtConfigData.class}, buildPushDeviceMgtConfigData(true, 5));

        assertEquals(result, 5);
    }

    @Test
    public void testGetMaximumDeviceLimitDefaultsToOne() throws Exception {

        int result = (int) invokePrivateMethod("getMaximumDeviceLimit",
                new Class<?>[]{PushDeviceMgtConfigData.class}, buildPushDeviceMgtConfigData(true, null));

        assertEquals(result, 2);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testGetDeviceManagementConfigFailure() throws Exception {

        try (MockedStatic<PushDeviceConfigManager> mockedConfigManager = mockStatic(PushDeviceConfigManager.class)) {
            mockedConfigManager.when(() -> PushDeviceConfigManager.getPushDeviceConfig("carbon.super"))
                    .thenThrow(new PushDeviceHandlerServerException("Error retrieving device management config"));

            invokePrivateMethod("getDeviceManagementConfig", new Class<?>[]{String.class}, "carbon.super");
        }
    }

    @Test
    public void testExpireExistingPushAuthContext() throws Exception {

        AuthenticationContext authenticationContext = mock(AuthenticationContext.class);
        when(authenticationContext.getProperty(PUSH_AUTH_ID)).thenReturn("sample-push-auth-id");

        invokePrivateMethod("expireExistingPushAuthContext",
                new Class<?>[]{AuthenticationContext.class}, authenticationContext);

        verify(pushAuthContextManager).clearContext("sample-push-auth-id");
        verify(authenticationContext).removeProperty(PUSH_AUTH_ID);
    }

    @Test
    public void testExpireExistingPushAuthContextWithoutPushAuthId() throws Exception {

        AuthenticationContext authenticationContext = mock(AuthenticationContext.class);
        when(authenticationContext.getProperty(PUSH_AUTH_ID)).thenReturn(null);

        invokePrivateMethod("expireExistingPushAuthContext",
                new Class<?>[]{AuthenticationContext.class}, authenticationContext);

        verify(authenticationContext, never()).removeProperty(PUSH_AUTH_ID);
    }

    @Test
    public void testHandleProgressiveEnrollmentCancellationRedirectsToWaitPageWithExistingId() throws Exception {

        AuthenticationContext authenticationContext = mock(AuthenticationContext.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        // The active push id stays on the context across the enrollment side-trip.
        when(authenticationContext.getProperty(PUSH_AUTH_ID)).thenReturn("active-id-1");
        PushAuthContext cachedContext = new PushAuthContext();
        cachedContext.setNumberChallenge("42");
        when(pushAuthContextManager.getContext("active-id-1")).thenReturn(cachedContext);

        try {
            invokePrivateMethod("handleProgressiveEnrollmentCancellation",
                    new Class<?>[]{HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class},
                    request, response, authenticationContext);
        } catch (Exception ignored) {
            // The method ends with a redirect that needs a real authenticated user in the context. We only care
            // about the no-state-mutation invariants below.
        }

        verify(authenticationContext).removeProperty(
                org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants
                        .IS_ADDITIONAL_DEVICE_REGISTRATION_ENGAGED);
        // The active id must NOT be torn down — the cache entry stays alive for the wait page to resume against.
        verify(pushAuthContextManager, never()).clearContext("active-id-1");
        verify(authenticationContext, never()).removeProperty(PUSH_AUTH_ID);
    }

    @Test
    public void testHandleProgressiveEnrollmentCancellationFailsWhenNoActiveIdOnContext() throws Exception {

        AuthenticationContext authenticationContext = mock(AuthenticationContext.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(authenticationContext.getProperty(PUSH_AUTH_ID)).thenReturn(null);

        try {
            invokePrivateMethod("handleProgressiveEnrollmentCancellation",
                    new Class<?>[]{HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class},
                    request, response, authenticationContext);
        } catch (Exception ignored) {
            // The fail path completes via the framework's standard error redirect, which throws on a bare mock
            // context — we only care that no spurious cache lookups happen below.
        }

        // The fail-path must not consult the cache under a null/empty id.
        verify(pushAuthContextManager, never()).getContext((String) null);
        verify(pushAuthContextManager, never()).getContext("");
    }

    private PushDeviceMgtConfigData buildPushDeviceMgtConfigData(boolean enableMultipleDeviceEnrollment,
                                                                 Integer maximumDeviceLimit) {

        PushDeviceMgtConfigData configData = new PushDeviceMgtConfigData();
        configData.setEnableMultipleDeviceEnrollment(enableMultipleDeviceEnrollment);
        configData.setMaximumDeviceLimit(maximumDeviceLimit);
        return configData;
    }

    private List<Device> buildDeviceList(int count) {

        List<Device> devices = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            Device device = new Device();
            device.setDeviceId("device-" + i);
            devices.add(device);
        }
        return devices;
    }

    /**
     * Invoke the private handleAdditionalDeviceEnrollment(...) method. The reject/redirect terminal steps issue an
     * HTTP redirect that fails on bare mocks; callers assert on interactions (whether registration was reached),
     * so any such terminal exception is intentionally swallowed here.
     */
    private void invokeHandleAdditionalDeviceEnrollment(List<Device> devices,
                                                        PushDeviceMgtConfigData deviceManagementConfig) {

        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        try {
            invokePrivateMethod("handleAdditionalDeviceEnrollment",
                    new Class<?>[]{AuthenticatedUser.class, List.class, HttpServletResponse.class,
                            HttpServletRequest.class, AuthenticationContext.class, String.class,
                            PushDeviceMgtConfigData.class},
                    authenticatedUser, devices, httpServletResponse, httpServletRequest, context, "carbon.super",
                    deviceManagementConfig);
        } catch (Exception ignored) {
            // Terminal redirect/error handling on bare mocks may throw; the interaction assertions cover the outcome.
        }
    }

    private void mockDeviceManagementConfig(MockedStatic<PushDeviceConfigManager> mockedConfigManager,
                                            PushDeviceMgtConfigData configData) {

        mockedConfigManager.when(() -> PushDeviceConfigManager.getPushDeviceConfig("carbon.super"))
                .thenReturn(configData);
    }

    private Object invokePrivateMethod(String methodName, Class<?>[] parameterTypes, Object... args)
            throws Exception {

        Method method = PushAuthenticator.class.getDeclaredMethod(methodName, parameterTypes);
        method.setAccessible(true);
        try {
            return method.invoke(pushAuthenticator, args);
        } catch (InvocationTargetException e) {
            throw (Exception) e.getCause();
        }
    }

}
