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
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.local.auth.push.authenticator.exception.PushAuthenticatorServerException;
import org.wso2.carbon.identity.local.auth.push.authenticator.model.PushAuthContext;
import org.wso2.carbon.identity.local.auth.push.authenticator.util.AuthenticatorUtils;

import java.lang.reflect.Field;
import java.nio.file.Paths;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.AuthenticatorPromptType.INTERNAL_PROMPT;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.SHOW_AUTH_FAILURE_REASON_PAGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ConnectorConfig.ENABLE_PUSH_NUMBER_CHALLENGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ConnectorConfig.RESEND_NOTIFICATION_MAX_ATTEMPTS;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_PUSH_AUTH_ID_NOT_FOUND;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTHENTICATOR_I18_KEY;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTH_ID;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTH_WAIT_PAGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.SCENARIO;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ScenarioTypes.LOGOUT;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ScenarioTypes.PUSH_DEVICE_ENROLLMENT;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ScenarioTypes.SEND_PUSH_NOTIFICATION;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.USERNAME;

public class PushAuthenticatorTest {

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

    @Mock
    ServiceURL serviceURL;

    @InjectMocks
    PushAuthenticator pushAuthenticator;

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
    public void testRedirectToAuthFailureReasonPage() {

        assertTrue(pushAuthenticator.redirectToAuthFailureReasonPage());
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
    }

    @Test
    public void testHandleAuthErrorReasonScenario() {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        try {
            throw pushAuthenticator.handleAuthErrorReasonScenario(
                    authenticationContext, ERROR_CODE_PUSH_AUTH_ID_NOT_FOUND);
        } catch (AuthenticationFailedException e) {
            assertTrue(authenticationContext.getProperty(SHOW_AUTH_FAILURE_REASON_PAGE) != null
                    && (Boolean) authenticationContext.getProperty(SHOW_AUTH_FAILURE_REASON_PAGE));
        }
    }

    @Test
    public void testGetMaximumResendAttempts() throws PushAuthenticatorServerException, AuthenticationFailedException {

        try (MockedStatic<AuthenticatorUtils> mockedUtils = mockStatic(AuthenticatorUtils.class)) {
            mockedUtils.when(
                    () -> AuthenticatorUtils.getPushAuthenticatorConfig(
                            RESEND_NOTIFICATION_MAX_ATTEMPTS, "carbon.super"))
                    .thenReturn("3");
            assertEquals(3, pushAuthenticator.getMaximumResendAttempts("carbon.super"));
        }
    }

    @Test
    public void testGetAuthInitiationData() throws AuthenticationFailedException, URLBuilderException {

        ExternalIdPConfig externalIdPConfig = mock(ExternalIdPConfig.class);
        when(context.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdPName()).thenReturn("externalIdP");

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
            assertEquals(expectedQueryString, queryParamsBuilder.toString());
        }
    }
}
