package org.wso2.carbon.identity.local.auth.push.authenticator.model;

import java.io.Serializable;

/**
 * Data holder for Push Authentication Context.
 */
public class PushAuthContext implements Serializable {

    private static final long serialVersionUID = 121973832655655099L;
    private String challenge;
    private String token;
    private String numberChallenge;
    private String deviceId;
    private String scenario;

    public PushAuthContext() {

    }

    public String getChallenge() {

        return challenge;
    }

    public void setChallenge(String challenge) {

        this.challenge = challenge;
    }

    public String getToken() {

        return token;
    }

    public void setToken(String token) {

        this.token = token;
    }

    public String getNumberChallenge() {

        return numberChallenge;
    }

    public void setNumberChallenge(String numberChallenge) {

        this.numberChallenge = numberChallenge;
    }

    public String getDeviceId() {

        return deviceId;
    }

    public void setDeviceId(String deviceId) {

        this.deviceId = deviceId;
    }

    public String getScenario() {

        return scenario;
    }

    public void setScenario(String scenario) {

        this.scenario = scenario;
    }
}
