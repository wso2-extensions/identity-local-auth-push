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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.equinox.http.helper.ContextPathServletAdaptor;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.local.auth.push.authenticator.context.PushAuthContextManager;
import org.wso2.carbon.identity.local.auth.push.servlet.PushAuthServlet;
import org.wso2.carbon.identity.local.auth.push.servlet.PushStatusServlet;
import org.wso2.carbon.identity.notification.push.device.handler.DeviceHandlerService;

import javax.servlet.Servlet;

import static org.wso2.carbon.identity.local.auth.push.servlet.constant.PushServletConstants.PUSH_AUTHENTICATE_SERVLET_URL;
import static org.wso2.carbon.identity.local.auth.push.servlet.constant.PushServletConstants.PUSH_STATUS_SERVLET_URL;

/**
 * Service component for Push Servlet.
 */
@Component(
        name = "org.wso2.carbon.identity.local.auth.push.servlet",
        immediate = true,
        service = PushServletServiceComponent.class
)
public class PushServletServiceComponent {

    private static final Log log = LogFactory.getLog(PushServletServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {

            HttpService httpService = PushServletDataHolder.getInstance().getHttpService();
            Servlet pushAuthenticateServlet = new ContextPathServletAdaptor(new PushAuthServlet(),
                    PUSH_AUTHENTICATE_SERVLET_URL);
            Servlet pushStatusServlet = new ContextPathServletAdaptor(new PushStatusServlet(),
                    PUSH_STATUS_SERVLET_URL);
            httpService.registerServlet(PUSH_AUTHENTICATE_SERVLET_URL, pushAuthenticateServlet, null, null);
            httpService.registerServlet(PUSH_STATUS_SERVLET_URL, pushStatusServlet, null, null);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Push servlet service component activated."
                                + "%n Authentication endpoint    : %s"
                                + "%n Check status endpoint      : %s",
                        PUSH_AUTHENTICATE_SERVLET_URL, PUSH_STATUS_SERVLET_URL));

            }
        } catch (Exception e) {
            String errMsg = "Error when registering Push endpoint services via the HttpService.";
            log.error(errMsg, e);
            throw new RuntimeException(errMsg, e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Push servlet service component deactivated.");
        }
    }

    @Reference(
            name = "osgi.http.service",
            service = HttpService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetHttpService"
    )
    protected void setHttpService(HttpService httpService) {

        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is set in Trusted App mgt bundle");
        }
        PushServletDataHolder.getInstance().setHttpService(httpService);
    }

    protected void unsetHttpService(HttpService httpService) {

        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is unset in the Trusted App mgt bundle");
        }
        PushServletDataHolder.getInstance().setHttpService(null);
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

        PushServletDataHolder.getInstance().setDeviceHandlerService(deviceHandlerService);
    }

    protected void unsetDeviceHandlerService(
            DeviceHandlerService deviceHandlerService) {

        PushServletDataHolder.getInstance().setDeviceHandlerService(null);
    }

    @Reference(
            name = "push.authenticator.context.manager",
            service = PushAuthContextManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetPushAuthContextManager"
    )
    protected void setPushAuthContextManager(PushAuthContextManager pushAuthContextManager) {

        PushServletDataHolder.getInstance().setPushAuthContextManager(pushAuthContextManager);
    }

    protected void unsetPushAuthContextManager(PushAuthContextManager pushAuthContextManager) {

        PushServletDataHolder.getInstance().setPushAuthContextManager(null);
    }
}
