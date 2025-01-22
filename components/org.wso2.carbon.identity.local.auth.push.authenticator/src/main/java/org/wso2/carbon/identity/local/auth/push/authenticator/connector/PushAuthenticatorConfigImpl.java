package org.wso2.carbon.identity.local.auth.push.authenticator.connector;

import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ConnectorConfig.ENABLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ConnectorConfig.ENABLE_PUSH_NUMBER_CHALLENGE;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ConnectorConfig.ENABLE_RESEND_NOTIFICATION_TIME;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.ConnectorConfig.RESEND_NOTIFICATION_MAX_ATTEMPTS;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.local.auth.push.authenticator.constant.AuthenticatorConstants.PUSH_AUTHENTICATOR_NAME;

/**
 * This class contains the authenticator config implementation.
 */
public class PushAuthenticatorConfigImpl implements IdentityConnectorConfig {

    @Override
    public String getName() {

        return PUSH_AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return PUSH_AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getCategory() {

        return "Multi Factor Authenticators";
    }

    @Override
    public String getSubCategory() {

        return "DEFAULT";
    }

    @Override
    public int getOrder() {

        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(ENABLE_PUSH_NUMBER_CHALLENGE, "Enable Number Challenge");
        nameMapping.put(ENABLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT, "Enable Progressive Enrollment");
        nameMapping.put(ENABLE_RESEND_NOTIFICATION_TIME, "Resend Notification Time");
        nameMapping.put(RESEND_NOTIFICATION_MAX_ATTEMPTS, "Resend Notification Max Attempts");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(ENABLE_PUSH_NUMBER_CHALLENGE, "Enable number challenge during push authentication.");
        descriptionMapping.put(ENABLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT, "Enable enrolling push notification devices" +
                " for users progressively during authentication.");
        descriptionMapping.put(ENABLE_RESEND_NOTIFICATION_TIME, "Number of seconds to enable resending the push " +
                "notification.");
        descriptionMapping.put(RESEND_NOTIFICATION_MAX_ATTEMPTS, "Maximum number of attempts to resend notification.");
        return descriptionMapping;
    }

    @Override
    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(ENABLE_PUSH_NUMBER_CHALLENGE);
        properties.add(ENABLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT);
        properties.add(ENABLE_RESEND_NOTIFICATION_TIME);
        properties.add(RESEND_NOTIFICATION_MAX_ATTEMPTS);
        return properties.toArray(new String[0]);
    }

    @Override
    public Properties getDefaultPropertyValues(String s) throws IdentityGovernanceException {

        String enablePushNumberChallenge = "false";
        String enablePushDeviceProgressiveEnrollment = "false";
        int enableResendNotificationInSeconds = 60;
        int resendNotificationMaxAttempts = 3;

        String enablePushNumberChallengeProperty = IdentityUtil.getProperty(ENABLE_PUSH_NUMBER_CHALLENGE);
        String enablePushDeviceProgressiveEnrollmentProperty =
                IdentityUtil.getProperty(ENABLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT);
        String enableResendNotificationInSecondsProperty = IdentityUtil.getProperty(ENABLE_RESEND_NOTIFICATION_TIME);
        String resendNotificationMaxAttemptsProperty = IdentityUtil.getProperty(RESEND_NOTIFICATION_MAX_ATTEMPTS);

        if (enablePushNumberChallengeProperty != null) {
            enablePushNumberChallenge = enablePushNumberChallengeProperty;
        }
        if (enablePushDeviceProgressiveEnrollmentProperty != null) {
            enablePushDeviceProgressiveEnrollment = enablePushDeviceProgressiveEnrollmentProperty;
        }
        if (enableResendNotificationInSecondsProperty != null) {
            enableResendNotificationInSeconds = Integer.parseInt(enableResendNotificationInSecondsProperty);
        }
        if (resendNotificationMaxAttemptsProperty != null) {
            resendNotificationMaxAttempts = Integer.parseInt(resendNotificationMaxAttemptsProperty);
        }

        Map<String, String> defaultProperties = new HashMap<>();
        defaultProperties.put(ENABLE_PUSH_NUMBER_CHALLENGE, enablePushNumberChallenge);
        defaultProperties.put(ENABLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT, enablePushDeviceProgressiveEnrollment);
        defaultProperties.put(ENABLE_RESEND_NOTIFICATION_TIME, String.valueOf(enableResendNotificationInSeconds));
        defaultProperties.put(RESEND_NOTIFICATION_MAX_ATTEMPTS, String.valueOf(resendNotificationMaxAttempts));

        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s) throws IdentityGovernanceException {

        return null;
    }
}
