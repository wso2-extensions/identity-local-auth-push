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

package org.wso2.carbon.identity.local.auth.push.servlet.internal;

import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.local.auth.push.authenticator.context.PushAuthContextManager;
import org.wso2.carbon.identity.notification.push.device.handler.DeviceHandlerService;

/**
 * Push Servlet Data Holder.
 */
public class PushServletDataHolder {

    private static final PushServletDataHolder instance = new PushServletDataHolder();

    private HttpService httpService;
    private static DeviceHandlerService deviceHandlerService;
    private static PushAuthContextManager pushAuthContextManager;

    private PushServletDataHolder() {

    }

    public static PushServletDataHolder getInstance() {

        return instance;
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

        PushServletDataHolder.deviceHandlerService = deviceHandlerService;
    }

    public PushAuthContextManager getPushAuthContextManager() {

        return pushAuthContextManager;
    }

    public void setPushAuthContextManager(PushAuthContextManager pushAuthContextManager) {

        PushServletDataHolder.pushAuthContextManager = pushAuthContextManager;
    }

}
