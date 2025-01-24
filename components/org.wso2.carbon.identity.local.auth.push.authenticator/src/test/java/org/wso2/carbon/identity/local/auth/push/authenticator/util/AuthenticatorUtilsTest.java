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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.push.authenticator.exception.PushAuthenticatorServerException;
import org.wso2.carbon.identity.local.auth.push.authenticator.internal.AuthenticatorDataHolder;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test class for AuthenticatorUtils.
 */
public class AuthenticatorUtilsTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private IdentityGovernanceService identityGovernanceService;

    @BeforeMethod
    public void setUp() {

        request = mock(HttpServletRequest.class);
        identityGovernanceService = mock(IdentityGovernanceService.class);
    }

    @Test
    public void testGetMultiOptionURIQueryString() {

        when(request.getParameter("multiOptionURI")).thenReturn("testURI");
        String result = AuthenticatorUtils.getMultiOptionURIQueryString(request);
        Assert.assertEquals(result, "&multiOptionURI=testURI");
    }

    @Test
    public void testGetMultiOptionURIQueryString_NullRequest() {

        String result = AuthenticatorUtils.getMultiOptionURIQueryString(null);
        Assert.assertEquals(result, "");
    }

    @Test
    public void testMaskIfRequired() {

        try (MockedStatic<LoggerUtils> mockedLoggerUtils = Mockito.mockStatic(LoggerUtils.class)) {
            mockedLoggerUtils.when(() -> LoggerUtils.getMaskedContent("testValue")).thenReturn("maskedValue");
            String result = AuthenticatorUtils.maskIfRequired("testValue");
            Assert.assertEquals(result, "testValue");
        }
    }

    @Test
    public void testGetPushAuthWaitPageUrl() throws AuthenticationFailedException, URLBuilderException {

        try (MockedStatic<ServiceURLBuilder> mockedServiceURLBuilder = Mockito.mockStatic(ServiceURLBuilder.class)) {
            ServiceURLBuilder serviceURLBuilder = mock(ServiceURLBuilder.class);
            ServiceURL serviceURL = mock(ServiceURL.class);

            mockedServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.addPath(AuthenticatorConstants.PUSH_AUTH_WAIT_PAGE)).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.build()).thenReturn(serviceURL);
            when(serviceURL.getAbsolutePublicURL()).thenReturn("http://example.com/wait");

            String result = AuthenticatorUtils.getPushAuthWaitPageUrl();
            Assert.assertEquals(result, "http://example.com/wait");
        }
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testGetPushAuthWaitPageUrl_Exception() throws URLBuilderException, AuthenticationFailedException {

        try (MockedStatic<ServiceURLBuilder> mockedServiceURLBuilder = Mockito.mockStatic(ServiceURLBuilder.class)) {
            ServiceURLBuilder serviceURLBuilder = mock(ServiceURLBuilder.class);
            mockedServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.addPath(AuthenticatorConstants.PUSH_AUTH_WAIT_PAGE)).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.build()).thenThrow(new URLBuilderException("Error"));

            AuthenticatorUtils.getPushAuthWaitPageUrl();
        }
    }

    @Test
    public void testGetPushAuthenticatorConfig() throws IdentityGovernanceException, PushAuthenticatorServerException {

        try (MockedStatic<AuthenticatorDataHolder> mockedAuthenticatorDataHolder = Mockito.mockStatic(
                AuthenticatorDataHolder.class)) {
            AuthenticatorDataHolder authenticatorDataHolder = mock(AuthenticatorDataHolder.class);
            mockedAuthenticatorDataHolder.when(AuthenticatorDataHolder::getInstance)
                    .thenReturn(authenticatorDataHolder);
            when(authenticatorDataHolder.getIdentityGovernanceService()).thenReturn(identityGovernanceService);

            Property property = new Property();
            property.setValue("testValue");
            when(identityGovernanceService.getConfiguration(new String[] {"testKey"}, "testTenant")).thenReturn(
                    new Property[] {property});

            String result = AuthenticatorUtils.getPushAuthenticatorConfig("testKey", "testTenant");
            Assert.assertEquals(result, "testValue");
        }
    }

    @Test(expectedExceptions = PushAuthenticatorServerException.class)
    public void testGetPushAuthenticatorConfig_Exception()
            throws IdentityGovernanceException, PushAuthenticatorServerException {

        try (MockedStatic<AuthenticatorDataHolder> mockedAuthenticatorDataHolder = Mockito.mockStatic(
                AuthenticatorDataHolder.class)) {
            AuthenticatorDataHolder authenticatorDataHolder = mock(AuthenticatorDataHolder.class);
            mockedAuthenticatorDataHolder.when(AuthenticatorDataHolder::getInstance)
                    .thenReturn(authenticatorDataHolder);
            when(authenticatorDataHolder.getIdentityGovernanceService()).thenReturn(identityGovernanceService);

            when(identityGovernanceService.getConfiguration(new String[] {"testKey"}, "testTenant")).thenThrow(
                    new IdentityGovernanceException("Error"));

            AuthenticatorUtils.getPushAuthenticatorConfig("testKey", "testTenant");
        }
    }

    @Test
    public void testGetRegistrationPageUrl() throws AuthenticationFailedException, URLBuilderException {

        try (MockedStatic<ServiceURLBuilder> mockedServiceURLBuilder = Mockito.mockStatic(ServiceURLBuilder.class)) {
            ServiceURLBuilder serviceURLBuilder = mock(ServiceURLBuilder.class);
            ServiceURL serviceURL = mock(ServiceURL.class);

            mockedServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.addPath(AuthenticatorConstants.PUSH_DEVICE_REGISTRATION_PAGE)).thenReturn(
                    serviceURLBuilder);
            when(serviceURLBuilder.build()).thenReturn(serviceURL);
            when(serviceURL.getAbsolutePublicURL()).thenReturn("http://example.com/register");

            String result = AuthenticatorUtils.getRegistrationPageUrl();
            Assert.assertEquals(result, "http://example.com/register");
        }
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testGetRegistrationPageUrl_Exception() throws URLBuilderException, AuthenticationFailedException {

        try (MockedStatic<ServiceURLBuilder> mockedServiceURLBuilder = Mockito.mockStatic(ServiceURLBuilder.class)) {
            ServiceURLBuilder serviceURLBuilder = mock(ServiceURLBuilder.class);
            mockedServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.addPath(AuthenticatorConstants.PUSH_DEVICE_REGISTRATION_PAGE)).thenReturn(
                    serviceURLBuilder);
            when(serviceURLBuilder.build()).thenThrow(new URLBuilderException("Error"));

            AuthenticatorUtils.getRegistrationPageUrl();
        }
    }

    @Test
    public void testGetPushDeviceEnrollConsentPageUrl() throws AuthenticationFailedException, URLBuilderException {

        try (MockedStatic<ServiceURLBuilder> mockedServiceURLBuilder = Mockito.mockStatic(ServiceURLBuilder.class)) {
            ServiceURLBuilder serviceURLBuilder = mock(ServiceURLBuilder.class);
            ServiceURL serviceURL = mock(ServiceURL.class);

            mockedServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.addPath(AuthenticatorConstants.PUSH_DEVICE_ENROLL_CONSENT_PAGE)).thenReturn(
                    serviceURLBuilder);
            when(serviceURLBuilder.build()).thenReturn(serviceURL);
            when(serviceURL.getAbsolutePublicURL()).thenReturn("http://example.com/consent");

            String result = AuthenticatorUtils.getPushDeviceEnrollConsentPageUrl();
            Assert.assertEquals(result, "http://example.com/consent");
        }
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testGetPushDeviceEnrollConsentPageUrl_Exception()
            throws URLBuilderException, AuthenticationFailedException {

        try (MockedStatic<ServiceURLBuilder> mockedServiceURLBuilder = Mockito.mockStatic(ServiceURLBuilder.class)) {
            ServiceURLBuilder serviceURLBuilder = mock(ServiceURLBuilder.class);
            mockedServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.addPath(AuthenticatorConstants.PUSH_DEVICE_ENROLL_CONSENT_PAGE))
                    .thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.build()).thenThrow(new URLBuilderException("Error"));

            AuthenticatorUtils.getPushDeviceEnrollConsentPageUrl();
        }
    }

    @Test
    public void testGetPushAuthPErrorPageUrl() throws AuthenticationFailedException, URLBuilderException {

        try (MockedStatic<ServiceURLBuilder> mockedServiceURLBuilder = Mockito.mockStatic(ServiceURLBuilder.class)) {
            ServiceURLBuilder serviceURLBuilder = mock(ServiceURLBuilder.class);
            ServiceURL serviceURL = mock(ServiceURL.class);

            mockedServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.addPath(AuthenticatorConstants.ERROR_PAGE)).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.build()).thenReturn(serviceURL);
            when(serviceURL.getAbsolutePublicURL()).thenReturn("http://example.com/error");

            String result = AuthenticatorUtils.getPushAuthPErrorPageUrl();
            Assert.assertEquals(result, "http://example.com/error");
        }
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testGetPushAuthPErrorPageUrl_Exception() throws URLBuilderException, AuthenticationFailedException {

        try (MockedStatic<ServiceURLBuilder> mockedServiceURLBuilder = Mockito.mockStatic(ServiceURLBuilder.class)) {
            ServiceURLBuilder serviceURLBuilder = mock(ServiceURLBuilder.class);
            mockedServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.addPath(AuthenticatorConstants.ERROR_PAGE)).thenReturn(serviceURLBuilder);
            when(serviceURLBuilder.build()).thenThrow(new URLBuilderException("Error"));

            AuthenticatorUtils.getPushAuthPErrorPageUrl();
        }
    }
}
