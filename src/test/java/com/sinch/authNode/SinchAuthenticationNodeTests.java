package com.sinch.authNode;

import com.sun.identity.idm.AMIdentity;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Optional;

import static java.util.Collections.emptyList;
import static org.forgerock.json.JsonValue.*;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

public class SinchAuthenticationNodeTests {

    @Mock
    private SinchAuthenticationNode.Config config;

    @Mock
    private Realm realm;

    @Mock
    private CoreWrapper coreWrapper;

    @Mock
    private AMIdentity mockUser;

    private SinchAuthenticationNode sinchAuthenticationNode;
    private TreeContext context;

    @BeforeEach
    public void setup() throws Exception {
        context = new TreeContext(retrieveSharedState(), json(object()),
                new ExternalRequestContext.Builder().build(), emptyList(), Optional.of("mockUserId"));
        MockitoAnnotations.openMocks(this);
        sinchAuthenticationNode = new SinchAuthenticationNode(config, realm, coreWrapper);
    }

    private JsonValue retrieveSharedState() {
        return json(object(field(USERNAME, "demo")));
    }

    @Test
    public void testProcessActionWhenNoUserPhoneInProfile() {
        Action result = sinchAuthenticationNode.process(context);
//        Assertions.assertFalse(result.callbacks.isEmpty());
    }

}
