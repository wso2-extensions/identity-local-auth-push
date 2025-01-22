package org.wso2.carbon.identity.local.auth.push.authenticator.constant;

/**
 * Constants related to the push notification authenticator.
 */
public class AuthenticatorConstants {

    private AuthenticatorConstants() {

    }

    public static final String PUSH_AUTHENTICATOR_NAME = "push-notification-authenticator";
    public static final String PUSH_AUTHENTICATOR_FRIENDLY_NAME = "Push Notification";
    public static final String PUSH_AUTHENTICATOR_I18_KEY = "authenticator.push.notification";

    public static final String PUSH_AUTHENTICATOR_ERROR_PREFIX = "PNA";

    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";
    public static final String AUTHENTICATORS = "authenticators=";
    public static final String IDF_HANDLER_NAME = "IdentifierExecutor";
    public static final String LOCAL_AUTHENTICATOR = "LOCAL";
    public static final String IS_LOGIN_ATTEMPT_BY_INVALID_USER = "isLoginAttemptByInvalidUser";
    public static final String INVALID_USERNAME = "invalidUsername";

    public static final String PUSH_ID = "pushId";
    public static final String PUSH_AUTH_ID = "pushAuthId";
    public static final String DEVICE_TOKEN = "deviceToken";
    public static final String NOTIFICATION_PROVIDER = "notificationProvider";
    public static final String CHALLENGE = "challenge";
    public static final String NUMBER_CHALLENGE = "numberChallenge";
    public static final String IP_ADDRESS = "ipAddress";
    public static final String REQUEST_DEVICE_OS = "deviceOS";
    public static final String REQUEST_DEVICE_BROWSER = "browser";

    public static final String PUSH_AUH_USER_CONSENT = "pushAuthUserConsent";

    public static final String AUTHENTICATOR_MESSAGE = "authenticatorMessage";
    public static final String PUSH_NOTIFICATION_SENT = "PushNotificationSent";

    public static final String PUSH_NOTIFICATION_EVENT_NAME = "TRIGGER_PUSH_NOTIFICATION";

    public static final String PUSH_NOTIFICATION_CHANNEL = "PUSH_NOTIFICATION";

    public static final String USER_AGENT = "user-agent";

    public static final String IS_DEVICE_REGISTRATION_CONSENT_GIVEN = "isDeviceRegistrationConsentGiven";

    // Endpoint URLs.
    public static final String PUSH_AUTH_WAIT_PAGE = "authenticationendpoint/pushAuth.jsp";
    public static final String PUSH_DEVICE_REGISTRATION_PAGE = "authenticationendpoint/pushEnroll.jsp";
    public static final String PUSH_DEVICE_ENROLL_CONSENT_PAGE = "authenticationendpoint/pushDeviceEnrollConsent.jsp";
    public static final String ERROR_PAGE = "authenticationendpoint/pushAuthError.jsp";

    // Query params.
    public static final String AUTHENTICATORS_QUERY_PARAM = "&authenticators=";
    public static final String RETRY_QUERY_PARAMS = "&authFailure=true&authFailureMsg=authentication.fail.message";
    public static final String ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS =
            "&authFailure=true&authFailureMsg=user.account.locked";
    public static final String ERROR_USER_RESEND_COUNT_EXCEEDED_QUERY_PARAMS =
            "&authFailure=true&authFailureMsg=error.push.resent.count.exceeded";
    public static final String ERROR_USER_DENIED_CONSENT_QUERY_PARAMS =
            "&authFailure=true&authFailureMsg=error.push.user.denied.consent";
    public static final String ERROR_NUMBER_CHALLENGE_FAILED_QUERY_PARAMS =
            "&authFailure=true&authFailureMsg=error.push.number.challenge.failed";
    public static final String ERROR_TOKEN_RESPONSE_FAILURE_QUERY_PARAMS =
            "&authFailure=true&authFailureMsg=error.push.token.response.failure";
    public static final String ERROR_PUSH_INTERNAL_ERROR_QUERY_PARAMS =
            "&authFailure=true&authFailureMsg=error.push.internal.error";
    public static final String ERROR_USER_REGISTERED_DEVICE_NOT_FOUND =
            "&authFailure=true&authFailureMsg=error.push.registered.device.not.found";
    public static final String ERROR_PUSH_AUTHENTICATION_FAILED =
            "&authFailure=true&authFailureMsg=error.push.authentication.failed";
    public static final String SCREEN_VALUE_QUERY_PARAM = "&screenValue=";
    public static final String UNLOCK_QUERY_PARAM = "&unlockTime=";
    public static final String MULTI_OPTION_URI_PARAM = "&multiOptionURI=";
    public static final String RECAPTCHA_PARAM = "&reCaptcha=";
    public static final String USERNAME_PARAM = "&username=";
    public static final String PUSH_AUTH_ID_PARAM = "&pushAuthId=";
    public static final String NUMBER_CHALLENGE_PARAM = "&numberChallenge=";
    public static final String ENROLL_DATA_PARAM = "&pushEnrollData=";
    public static final String TENANT_DOMAIN_PARAM = "&tenantDomain=";

    public static final String NOTIFICATION_RESEND_ATTEMPTS = "notificationResendAttempts";
    public static final int DEFAULT_NOTIFICATION_RESEND_ATTEMPTS = 5;

    public static final String SCENARIO = "scenario";
    public static final String NOTIFICATION_SCENARIO = "NOTIFICATION_SCENARIO";

    // JWT token claim values.
    public static final String TOKEN_AUTH_STATUS = "response";
    public static final String TOKEN_AUTH_CHALLENGE = "challenge";
    public static final String TOKEN_NUMBER_CHALLENGE = "numberChallenge";

    public static final String AUTH_REQUEST_STATUS_APPROVED = "APPROVED";
    public static final String AUTH_REQUEST_STATUS_DENIED = "DENIED";

    public static final String PUSH_AUTH_CONTEXT_CACHE = "PushAuthContextCache";

    public static final String PUSH_AUTH_FAILED_ATTEMPTS_CLAIM =
            "http://wso2.org/claims/identity/failedPushAuthAttempts";

    // Auth error messages to be sent in the url in failure scenarios.
    public static final String PUSH_AUTH_FAIL_INTERNAL_ERROR = "Push Authentication Failed due to internal error";
    public static final String PUSH_AUTH_FAIL_USER_DENIED = "User denied the push authentication request";
    public static final String PUSH_AUTH_FAIL_NUMBER_CHALLENGE_FAILED = "Number challenge failed for " +
            "the push authentication request";
    public static final String PUSH_AUTH_FAIL_TOKEN_RESPONSE_FAILED = "Token response validation failed for " +
            "the push authentication request";

    /**
     * Authentication flow scenarios associated with the authenticator.
     */
    public enum ScenarioTypes {

        SEND_PUSH_NOTIFICATION("SEND_PUSH_NOTIFICATION"),
        RESEND_PUSH_NOTIFICATION("RESEND_PUSH_NOTIFICATION"),
        PROCEED_PUSH_AUTHENTICATION("PROCEED_PUSH_AUTHENTICATION"),
        PUSH_DEVICE_ENROLLMENT("PUSH_DEVICE_ENROLLMENT"),
        INIT_PUSH_ENROLL("INIT_PUSH_ENROLL"),
        CANCEL_PUSH_ENROLL("CANCEL_PUSH_ENROLL"),
        PUSH_AUTHENTICATION("PUSH_AUTHENTICATION"),
        LOGOUT("LOGOUT");

        private final String value;

        ScenarioTypes(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * Enum for connector configurations.
     */
    public static class ConnectorConfig {

        public static final String ENABLE_PUSH_DEVICE_PROGRESSIVE_ENROLLMENT = "PUSH.EnableProgressiveEnrollment";
        public static final String ENABLE_PUSH_NUMBER_CHALLENGE = "PUSH.EnableNumberChallenge";
        public static final String ENABLE_RESEND_NOTIFICATION_TIME = "PUSH.ResendNotificationTime";
        public static final String RESEND_NOTIFICATION_MAX_ATTEMPTS = "PUSH.ResendNotificationMaxAttempts";
    }

    /**
     * Enum for notification scenario types.
     */
    public enum NotificationScenarioTypes {

        PUSH_AUTHENTICATION("AUTHENTICATION"),
        PUSH_DEVICE_ENROLLMENT("ENROLLMENT");

        private final String value;

        NotificationScenarioTypes(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * Enum for error messages.
     */
    public enum ErrorMessages {

        ERROR_CODE_ERROR_GETTING_CONFIG("65001", "Error occurred while getting the authenticator " +
                "configuration"),
        ERROR_CODE_EMPTY_USERNAME("65002", "Username can not be empty"),
        ERROR_CODE_NO_USER_FOUND("65003", "No user found from the authentication steps"),
        ERROR_CODE_NO_FEDERATED_USER("65004", "No federated user found"),
        ERROR_CODE_ERROR_REDIRECTING_TO_LOGIN_PAGE("65005",
                "Error occurred while redirecting to the login page"),
        ERROR_CODE_ERROR_REDIRECTING_TO_DEVICE_REGISTRATION_PAGE("65006",
                "Error occurred while redirecting to the device registration page"),
        ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR("65007", "No IDP found with the name: " +
                "%s in tenant: %s"),
        ERROR_CODE_ERROR_GETTING_FEDERATED_AUTHENTICATOR("65008", "Error occurred while getting IDP: " +
                "%s from tenant: %s"),
        ERROR_CODE_GETTING_ACCOUNT_STATE("65009", "Error occurred while checking the account locked " +
                "state for the user: %s"),
        ERROR_CODE_ERROR_GETTING_USER_REALM("65010",
                "Error occurred while getting the user realm for tenant: %s"),
        ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER("65011",
                "Error occurred while getting the user store manager for the user: %s"),
        ERROR_CODE_ERROR_GETTING_ACCOUNT_UNLOCK_TIME("65012",
                "Error occurred while getting account unlock time for user: %s"),
        ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE("65013",
                "Error occurred while redirecting to the error page"),
        ERROR_CODE_ERROR_TRIGGERING_EVENT("65014",
                "Error occurred while triggering event: %s for the user: %s"),
        ERROR_CODE_ERROR_GETTING_USER_ID("65015",
                "Error occurred while getting the user ID for the user: %s"),
        ERROR_CODE_USER_ACCOUNT_LOCKED("65016", "Account is locked for the user: %s"),
        ERROR_CODE_RETRYING_PUSH_NOTIFICATION_RESEND("65017",
                "User: %s is retrying to resend the push notification"),
        ERROR_CODE_PUSH_AUTH_CONTEXT_NOT_FOUND("65018", "No push authentication context found" +
                " for user: %s"),
        ERROR_CODE_PUSH_AUTH_ID_NOT_FOUND("65019", "No push authentication ID found in push " +
                "authentication context"),
        ERROR_CODE_PUSH_AUTH_RESPONSE_TOKEN_NOT_FOUND("65020", "No response token found in push " +
                "authentication context for user: %s"),
        ERROR_CODE_DEVICE_ID_NOT_FOUND("65021", "No device ID found in push authentication context" +
                " for user: %s"),
        ERROR_CODE_RESPONSE_TOKEN_VALIDATION_FAILED("65022", "Response token validation failed for " +
                "token received from device ID: %s"),
        ERROR_CODE_CLAIMSET_NOT_FOUND_IN_RESPONSE_TOKEN("65023", "Claim set not found in response " +
                "token received from device ID: %s"),
        ERROR_CODE_PUSH_AUTH_CHALLENGE_VALIDATION_FAILED("65024", "Puss auth challenge validation " +
                "failed for response token received from device ID: %s"),
        ERROR_CODE_PUSH_NUMBER_CHALLENGE_VALIDATION_FAILED("65025", "Puss auth number challenge " +
                "validation failed for response token received from device ID: %s"),
        ERROR_CODE_ERROR_GETTING_AUTH_STATUS_FROM_TOKEN("65026", "Error occurred while getting " +
                "the authentication status from the token received from device ID: %s"),
        ERROR_CODE_ERROR_INVALID_AUTH_STATUS_FROM_TOKEN("65027", "Invalid authentication status " +
                "received from the token received from device ID: %s"),
        ERROR_CODE_ERROR_GETTING_USER_DEVICE("65028", "Error occurred while getting the user device " +
                "for user: %s"),
        ERROR_CODE_ERROR_GETTING_USER_DEVICE_PUBLIC_KEY("65029", "Error occurred while getting the user " +
                "device public key for user: %s"),
        ERROR_CODE_ERROR_REDIRECTING_TO_IDF_PAGE("65030", "Error while redirecting to the login page."),
        ERROR_CODE_ERROR_DEVICE_NOT_REGISTERED_AND_CONSENT_NOT_GIVEN("65031", "Device not registered " +
                "and request for use consent to register new device."),
        ERROR_CODE_PUSH_AUTH_USER_DENIED("65032", "User denied the push authentication request for " +
                "username: %s"),
        ERROR_CODE_AUTHENTICATION_CONTEXT_NOT_FOUND("65033", "Authentication context not found."),
        ERROR_CODE_ERROR_BUILDING_STATUS_URL("65034", "Error occurred while building status check URL."),;

        private final String code;
        private final String message;

        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        public String getCode() {

            return PUSH_AUTHENTICATOR_ERROR_PREFIX + "-" + code;
        }

        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return code + " - " + message;
        }
    }

}
