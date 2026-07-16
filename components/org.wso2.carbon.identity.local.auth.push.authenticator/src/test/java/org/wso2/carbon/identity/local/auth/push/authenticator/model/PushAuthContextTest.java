/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.local.auth.push.authenticator.model;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

/**
 * Test class for PushAuthContext.
 */
public class PushAuthContextTest {

    private PushAuthContext pushAuthContext;

    @BeforeMethod
    public void setUp() {

        pushAuthContext = new PushAuthContext();
    }

    @Test
    public void testChallenge() {

        pushAuthContext.setChallenge("sampleChallenge");
        assertEquals(pushAuthContext.getChallenge(), "sampleChallenge");
    }

    @Test
    public void testToken() {

        pushAuthContext.setToken("sampleToken");
        assertEquals(pushAuthContext.getToken(), "sampleToken");
    }

    @Test
    public void testNumberChallenge() {

        pushAuthContext.setNumberChallenge("37");
        assertEquals(pushAuthContext.getNumberChallenge(), "37");
    }

    @Test
    public void testDeviceId() {

        pushAuthContext.setDeviceId("sampleDeviceId");
        assertEquals(pushAuthContext.getDeviceId(), "sampleDeviceId");
    }

    @Test
    public void testScenario() {

        pushAuthContext.setScenario("PUSH_AUTHENTICATION");
        assertEquals(pushAuthContext.getScenario(), "PUSH_AUTHENTICATION");
    }

    @Test
    public void testNotifiedDeviceIdsDefaultsToNull() {

        assertNull(pushAuthContext.getNotifiedDeviceIds());
    }

    @Test
    public void testNotifiedDeviceIds() {

        List<String> deviceIds = Arrays.asList("device-1", "device-2", "device-3");
        pushAuthContext.setNotifiedDeviceIds(deviceIds);

        assertEquals(pushAuthContext.getNotifiedDeviceIds(), deviceIds);
        assertEquals(pushAuthContext.getNotifiedDeviceIds().size(), 3);
        assertEquals(pushAuthContext.getNotifiedDeviceIds().get(0), "device-1");
    }

    @Test
    public void testRespondingDeviceIdDefaultsToNull() {

        assertNull(pushAuthContext.getRespondingDeviceId());
    }

    @Test
    public void testRespondingDeviceId() {

        pushAuthContext.setRespondingDeviceId("responding-device");
        assertEquals(pushAuthContext.getRespondingDeviceId(), "responding-device");
    }

    /**
     * A context serialized with the new field must deserialize with all fields intact. This guards the distributed
     * cache round-trip within a homogeneous (new) cluster.
     */
    @Test
    public void testSerializationRoundTripWithNewFields() throws Exception {

        pushAuthContext.setChallenge("challenge");
        pushAuthContext.setToken("token");
        pushAuthContext.setDeviceId("device-1");
        pushAuthContext.setNotifiedDeviceIds(Arrays.asList("device-1", "device-2"));
        pushAuthContext.setRespondingDeviceId("device-2");

        PushAuthContext deserialized = serializeAndDeserialize(pushAuthContext);

        assertEquals(deserialized.getChallenge(), "challenge");
        assertEquals(deserialized.getToken(), "token");
        assertEquals(deserialized.getDeviceId(), "device-1");
        assertEquals(deserialized.getNotifiedDeviceIds(), Arrays.asList("device-1", "device-2"));
        assertEquals(deserialized.getRespondingDeviceId(), "device-2");
    }

    /**
     * A legacy context (only the pre-existing deviceId populated, new fields left unset) must deserialize cleanly with
     * the new fields defaulting to null. This mirrors reading a context that was cached by an older node.
     */
    @Test
    public void testSerializationRoundTripLegacyContext() throws Exception {

        pushAuthContext.setDeviceId("legacy-device");

        PushAuthContext deserialized = serializeAndDeserialize(pushAuthContext);

        assertEquals(deserialized.getDeviceId(), "legacy-device");
        assertNull(deserialized.getNotifiedDeviceIds());
        assertNull(deserialized.getRespondingDeviceId());
    }

    private PushAuthContext serializeAndDeserialize(PushAuthContext context) throws Exception {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)) {
            objectOutputStream.writeObject(context);
        }
        try (ObjectInputStream objectInputStream = new ObjectInputStream(
                new ByteArrayInputStream(byteArrayOutputStream.toByteArray()))) {
            return (PushAuthContext) objectInputStream.readObject();
        }
    }
}
