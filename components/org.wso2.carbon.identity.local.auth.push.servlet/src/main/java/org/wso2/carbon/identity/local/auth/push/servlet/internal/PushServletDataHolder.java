package org.wso2.carbon.identity.local.auth.push.servlet.internal;

import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.local.auth.push.authenticator.PushAuthContextManager;
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

    public HttpService getHttpService() {

        return httpService;
    }

    public void setHttpService(HttpService httpService) {

        this.httpService = httpService;
    }
}
