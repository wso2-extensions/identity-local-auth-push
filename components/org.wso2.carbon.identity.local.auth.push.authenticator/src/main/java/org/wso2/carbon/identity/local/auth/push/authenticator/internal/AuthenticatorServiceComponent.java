package org.wso2.carbon.identity.local.auth.push.authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.identity.local.auth.push.authenticator.PushAuthContextManager;
import org.wso2.carbon.identity.local.auth.push.authenticator.PushAuthenticator;
import org.wso2.carbon.identity.local.auth.push.authenticator.connector.PushAuthenticatorConfigImpl;
import org.wso2.carbon.identity.local.auth.push.authenticator.impl.PushAuthContextManagerImpl;
import org.wso2.carbon.identity.notification.push.device.handler.DeviceHandlerService;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Push Authenticator Service Component.
 */
@Component(
        name = "org.wso2.carbon.identity.local.auth.push.authenticator",
        immediate = true
)
public class AuthenticatorServiceComponent {

    private static final Log LOG = LogFactory.getLog(AuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleContext = context.getBundleContext();
            bundleContext.registerService(ApplicationAuthenticator.class.getName(), new PushAuthenticator(), null);
            bundleContext.registerService(PushAuthContextManager.class.getName(),
                    new PushAuthContextManagerImpl(), null);
            bundleContext.registerService(IdentityConnectorConfig.class.getName(), new PushAuthenticatorConfigImpl(),
                    null);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Push Authenticator is activated");
            }
        } catch (Throwable e) {
            LOG.error("Error while activating the Push Authenticator", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Push Authenticator is deactivated");
        }
    }

    @Reference(
            name = "org.wso2.carbon.idp.mgt.IdpManager",
            service = IdpManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityProviderManagementService"
    )
    protected void setIdentityProviderManagementService(IdpManager idpManager) {

        AuthenticatorDataHolder.getInstance().setIdpManager(idpManager);
    }

    protected void unsetIdentityProviderManagementService(IdpManager idpManager) {

        AuthenticatorDataHolder.getInstance().setIdpManager(null);
    }

    @Reference(
            name = "AccountLockService",
            service = org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAccountLockService"
    )
    protected void setAccountLockService(AccountLockService accountLockService) {

        AuthenticatorDataHolder.getInstance().setAccountLockService(accountLockService);
    }

    protected void unsetAccountLockService(AccountLockService accountLockService) {

        AuthenticatorDataHolder.getInstance().setAccountLockService(null);
    }

    @Reference(
            name = "RealmService",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        AuthenticatorDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        AuthenticatorDataHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "EventMgtService",
            service = org.wso2.carbon.identity.event.services.IdentityEventService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityEventService")
    protected void setIdentityEventService(IdentityEventService eventService) {

        AuthenticatorDataHolder.getInstance().setIdentityEventService(eventService);
    }

    protected void unsetIdentityEventService(IdentityEventService eventService) {

        AuthenticatorDataHolder.getInstance().setIdentityEventService(null);
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = org.wso2.carbon.identity.governance.IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService idpManager) {

        AuthenticatorDataHolder.getInstance().setIdentityGovernanceService(idpManager);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService idpManager) {

        AuthenticatorDataHolder.getInstance().setIdentityGovernanceService(null);
    }

    @Reference(
            name = "org.wso2.carbon.identity.notification.push.device.handler",
            service = DeviceHandlerService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetDeviceHandlerService"
    )
    protected void setDeviceHandlerService(
            DeviceHandlerService deviceHandlerService) {

        AuthenticatorDataHolder.getInstance().setDeviceHandlerService(deviceHandlerService);
    }

    protected void unsetDeviceHandlerService(
            DeviceHandlerService deviceHandlerService) {

        AuthenticatorDataHolder.getInstance().setDeviceHandlerService(null);
    }

}
