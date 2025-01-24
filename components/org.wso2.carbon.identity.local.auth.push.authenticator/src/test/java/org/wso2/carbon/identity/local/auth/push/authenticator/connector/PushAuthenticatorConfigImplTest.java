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

package org.wso2.carbon.identity.local.auth.push.authenticator.connector;

import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;

import java.util.Map;
import java.util.Properties;

import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Test class for PushAuthenticatorConfigImpl.
 */
public class PushAuthenticatorConfigImplTest {

    private PushAuthenticatorConfigImpl pushAuthenticatorConfig;

    @BeforeMethod
    public void setUp() {

        MockitoAnnotations.openMocks(this);
        pushAuthenticatorConfig = new PushAuthenticatorConfigImpl();
    }

    @Test
    public void testGetName() {

        assertEquals(pushAuthenticatorConfig.getName(), "push-notification-authenticator");
    }

    @Test
    public void testGetFriendlyName() {

        assertEquals(pushAuthenticatorConfig.getFriendlyName(), "Push Notification");
    }

    @Test
    public void testGetCategory() {

        assertEquals(pushAuthenticatorConfig.getCategory(), "Multi Factor Authenticators");
    }

    @Test
    public void testGetSubCategory() {

        assertEquals(pushAuthenticatorConfig.getSubCategory(), "DEFAULT");
    }

    @Test
    public void testGetOrder() {

        assertEquals(pushAuthenticatorConfig.getOrder(), 0);
    }

    @Test
    public void testGetPropertyNameMapping() {

        Map<String, String> nameMapping = pushAuthenticatorConfig.getPropertyNameMapping();
        assertNotNull(nameMapping);
        assertEquals(nameMapping.get("PUSH.EnableNumberChallenge"), "Enable Number Challenge");
        assertEquals(nameMapping.get("PUSH.EnableProgressiveEnrollment"), "Enable Progressive Enrollment");
        assertEquals(nameMapping.get("PUSH.ResendNotificationTime"), "Resend Notification Time");
        assertEquals(nameMapping.get("PUSH.ResendNotificationMaxAttempts"), "Resend Notification Max Attempts");
    }

    @Test
    public void testGetPropertyDescriptionMapping() {

        Map<String, String> descriptionMapping = pushAuthenticatorConfig.getPropertyDescriptionMapping();
        assertNotNull(descriptionMapping);
        assertEquals(descriptionMapping.get("PUSH.EnableNumberChallenge"), "Enable number challenge during push " +
                "authentication.");
        assertEquals(descriptionMapping.get("PUSH.EnableProgressiveEnrollment"), "Enable enrolling push notification " +
                "devices for users progressively during authentication.");
        assertEquals(descriptionMapping.get("PUSH.ResendNotificationTime"), "Number of seconds to enable " +
                "resending the push notification.");
        assertEquals(descriptionMapping.get("PUSH.ResendNotificationMaxAttempts"), "Maximum number of attempts to " +
                "resend notification.");
    }

    @Test
    public void testGetPropertyNames() {

        String[] propertyNames = pushAuthenticatorConfig.getPropertyNames();
        assertNotNull(propertyNames);
        assertEquals(propertyNames.length, 4);
        assertEquals(propertyNames[0], "PUSH.EnableNumberChallenge");
        assertEquals(propertyNames[1], "PUSH.EnableProgressiveEnrollment");
        assertEquals(propertyNames[2], "PUSH.ResendNotificationTime");
        assertEquals(propertyNames[3], "PUSH.ResendNotificationMaxAttempts");
    }

    @Test
    public void testGetDefaultPropertyValues() throws IdentityGovernanceException {

        try (MockedStatic<IdentityUtil> mockedUtil = mockStatic(IdentityUtil.class)) {
            mockedUtil.when(() -> IdentityUtil.getProperty("PUSH.EnableNumberChallenge")).thenReturn("true");
            mockedUtil.when(() -> IdentityUtil.getProperty("PUSH.EnableProgressiveEnrollment")).thenReturn("true");
            mockedUtil.when(() -> IdentityUtil.getProperty("PUSH.ResendNotificationTime")).thenReturn("120");
            mockedUtil.when(() -> IdentityUtil.getProperty("PUSH.ResendNotificationMaxAttempts")).thenReturn("5");

            Properties properties = pushAuthenticatorConfig.getDefaultPropertyValues("carbon.super");
            assertNotNull(properties);
            assertEquals(properties.getProperty("PUSH.EnableNumberChallenge"), "true");
            assertEquals(properties.getProperty("PUSH.EnableProgressiveEnrollment"), "true");
            assertEquals(properties.getProperty("PUSH.ResendNotificationTime"), "120");
            assertEquals(properties.getProperty("PUSH.ResendNotificationMaxAttempts"), "5");
        }
    }
}
