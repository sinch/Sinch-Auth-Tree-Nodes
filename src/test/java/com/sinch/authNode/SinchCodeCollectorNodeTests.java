package com.sinch.authNode;

import com.sinch.authNode.service.SinchApiService;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import javax.security.auth.callback.*;
import java.util.List;
import java.util.Optional;

import static com.sinch.authNode.TestConstants.*;
import static java.util.Collections.emptyList;
import static org.forgerock.json.JsonValue.*;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

public class SinchCodeCollectorNodeTests {

    @Mock
    private SinchCodeCollectorCodeNode.Config config;

    @Mock
    private SinchApiService sinchApiService;

    private SinchCodeCollectorCodeNode sinchCodeCollectorCodeNode;
    private TreeContext context;

    @BeforeEach
    public void setup() throws Exception {
        context = new TreeContext(retrieveSharedState(), retrieveTransientState(),
                new ExternalRequestContext.Builder().build(), emptyList(), Optional.of("mockUserId"));
        MockitoAnnotations.openMocks(this).close();
        sinchCodeCollectorCodeNode = new SinchCodeCollectorCodeNode(config, sinchApiService);
    }

    @Test
    public void testProcessOutcomeWhenNoCodeInputHidden() {
        Mockito.when(config.isCodeHidden()).thenReturn(true);

        Action result = sinchCodeCollectorCodeNode.process(context);
        List<Callback> callbacks = result.callbacks;

        Assertions.assertEquals(2, callbacks.size());
        Assertions.assertEquals(TextOutputCallback.class, callbacks.get(0).getClass());
        Assertions.assertEquals(PasswordCallback.class, callbacks.get(1).getClass());
    }

    @Test
    public void testProcessOutcomeWhenNoCodeInputAsText() {
        Mockito.when(config.isCodeHidden()).thenReturn(false);

        Action result = sinchCodeCollectorCodeNode.process(context);
        List<Callback> callbacks = result.callbacks;

        Assertions.assertEquals(2, callbacks.size());
        Assertions.assertEquals(TextOutputCallback.class, callbacks.get(0).getClass());
        Assertions.assertEquals(NameCallback.class, callbacks.get(1).getClass());
    }

    private JsonValue retrieveSharedState() {
        return json(object(field(USERNAME, "demo"),
                field(SinchAuthenticationNode.INITIATED_ID_KEY, FAKE_ID),
                field(SinchAuthenticationNode.VER_METHOD_KEY, FAKE_METHOD.toString()),
                field(SinchAuthenticationNode.USER_PHONE_KEY, FAKE_NUM)));
    }

    private JsonValue retrieveTransientState() {
        return json(object(field(SinchAuthenticationNode.APP_HASH_KEY, FAKE_APP_HASH)));
    }

}
