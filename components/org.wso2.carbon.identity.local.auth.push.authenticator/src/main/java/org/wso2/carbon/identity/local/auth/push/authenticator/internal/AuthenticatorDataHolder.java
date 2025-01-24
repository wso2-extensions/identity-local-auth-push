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

package org.wso2.carbon.identity.local.auth.push.authenticator.internal;

import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.identity.notification.push.device.handler.DeviceHandlerService;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Push Authenticator Data Holder.
 */
public class AuthenticatorDataHolder {

    private static final AuthenticatorDataHolder instance = new AuthenticatorDataHolder();

    private static IdpManager idpManager;
    private static AccountLockService accountLockService;
    private static RealmService realmService;
    private static IdentityEventService identityEventService;
    private static DeviceHandlerService deviceHandlerService;
    private static IdentityGovernanceService identityGovernanceService;

    private AuthenticatorDataHolder() {

    }

    public static AuthenticatorDataHolder getInstance() {

        return instance;
    }

    /**
     * Get IdpManager.
     *
     * @return IdpManager.
     */
    public IdpManager getIdpManager() {

        return idpManager;
    }

    /**
     * Set IdpManager.
     *
     * @param idpManager IdpManager.
     */
    public void setIdpManager(IdpManager idpManager) {

        AuthenticatorDataHolder.idpManager = idpManager;
    }

    /**
     * Get Account Lock service.
     *
     * @return Account Lock service.
     */
    public AccountLockService getAccountLockService() {

        return accountLockService;
    }

    /**
     * Set Account Lock service.
     *
     * @param accountLockService Account Lock service.
     */
    public void setAccountLockService(AccountLockService accountLockService) {

        AuthenticatorDataHolder.accountLockService = accountLockService;
    }

    /**
     * Get the RealmService.
     *
     * @return RealmService.
     */
    public RealmService getRealmService() {

        return realmService;
    }

    /**
     * Set the RealmService.
     *
     * @param realmService RealmService.
     */
    public void setRealmService(RealmService realmService) {

        AuthenticatorDataHolder.realmService = realmService;
    }

    /**
     * Get IdentityEventService instance.
     *
     * @return IdentityEventService instance.
     */
    public IdentityEventService getIdentityEventService() {

        return identityEventService;
    }

    /**
     * Set IdentityEventService instance.
     *
     * @param identityEventService IdentityEventService instance.
     */
    public void setIdentityEventService(IdentityEventService identityEventService) {

        AuthenticatorDataHolder.identityEventService = identityEventService;
    }

    /**
     * Get IdentityGovernanceService instance.
     *
     * @return IdentityGovernanceService instance.
     */
    public IdentityGovernanceService getIdentityGovernanceService() {

        return identityGovernanceService;
    }

    /**
     * Set IdentityGovernanceService instance.
     *
     * @param identityGovernanceService IdentityGovernanceService instance.
     */
    public void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        AuthenticatorDataHolder.identityGovernanceService = identityGovernanceService;
    }

    /**
     * Get DeviceHandlerService instance.
     *
     * @return DeviceHandlerService instance.
     */
    public DeviceHandlerService getDeviceHandlerService() {

        return deviceHandlerService;
    }

    /**
     * Set DeviceHandlerService instance.
     *
     * @param deviceHandlerService DeviceHandlerService instance.
     */
    public void setDeviceHandlerService(DeviceHandlerService deviceHandlerService) {

        AuthenticatorDataHolder.deviceHandlerService = deviceHandlerService;
    }
}
