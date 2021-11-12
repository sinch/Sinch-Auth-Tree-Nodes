package com.sinch.authNode;

import com.sinch.authNode.service.SinchApiService;
import com.sinch.verification.model.verification.VerificationResponseData;
import com.sinch.verification.model.verification.VerificationStatus;
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

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import java.util.List;

import static com.sinch.authNode.TestConstants.*;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.forgerock.json.JsonValue.*;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.mockito.ArgumentMatchers.any;

public class SinchCodeCollectorNodeTests {

    @Mock
    private SinchCodeCollectorCodeNode.Config config;

    @Mock
    private SinchApiService sinchApiService;

    private SinchCodeCollectorCodeNode sinchCodeCollectorCodeNode;
    private TreeContext context;

    @BeforeEach
    public void setup() throws Exception {
        MockitoAnnotations.openMocks(this).close();
        context = buildTreeContext(emptyList());
        sinchCodeCollectorCodeNode = new SinchCodeCollectorCodeNode(config, sinchApiService);
        injectDefaultConfig();
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

    @Test
    public void testProcessWhenCodePassedAsPassword() {
        Mockito.when(config.isCodeHidden()).thenReturn(true);
        PasswordCallback passwordCallback = new PasswordCallback("prompt", false);
        passwordCallback.setPassword(FAKE_CODE.toCharArray());

        context = new TreeContext(retrieveSharedState(), retrieveTransientState(),
                new ExternalRequestContext.Builder().build(), singletonList(passwordCallback));
        mockVerifyCall(true);

        Action result = sinchCodeCollectorCodeNode.process(context);

        Mockito.verify(sinchApiService).verifySynchronicallyById(FAKE_APP_KEY, FAKE_APP_SECRET, FAKE_ID, FAKE_CODE, FAKE_METHOD.asSinchMethodType());
        Assertions.assertEquals("true", result.outcome);
    }

    @Test
    public void testProcessWhenCodePassedAsNameCallback() {
        Mockito.when(config.isCodeHidden()).thenReturn(false);
        NameCallback nameCallback = new NameCallback("prompt", "dn");
        nameCallback.setName(FAKE_CODE);

        context = new TreeContext(retrieveSharedState(), retrieveTransientState(),
                new ExternalRequestContext.Builder().build(), singletonList(nameCallback));
        mockVerifyCall(true);

        Action result = sinchCodeCollectorCodeNode.process(context);

        Mockito.verify(sinchApiService).verifySynchronicallyById(FAKE_APP_KEY, FAKE_APP_SECRET, FAKE_ID, FAKE_CODE, FAKE_METHOD.asSinchMethodType());
        Assertions.assertEquals("true", result.outcome);
    }

    @Test
    public void testProcessWithWrongCode() {
        Mockito.when(config.isCodeHidden()).thenReturn(true);
        PasswordCallback passwordCallback = new PasswordCallback("prompt", false);
        passwordCallback.setPassword(FAKE_CODE.toCharArray());
        mockVerifyCall(false);

        context = new TreeContext(retrieveSharedState(), retrieveTransientState(),
                new ExternalRequestContext.Builder().build(), singletonList(passwordCallback));
        Action result = sinchCodeCollectorCodeNode.process(context);

        Mockito.verify(sinchApiService).verifySynchronicallyById(FAKE_APP_KEY, FAKE_APP_SECRET, FAKE_ID, FAKE_CODE, FAKE_METHOD.asSinchMethodType());
        Assertions.assertEquals("false", result.outcome);
    }

    @Test
    public void testProcessWithApiException() {
        Mockito.when(config.isCodeHidden()).thenReturn(true);
        PasswordCallback passwordCallback = new PasswordCallback("prompt", false);
        passwordCallback.setPassword(FAKE_CODE.toCharArray());

        context = new TreeContext(retrieveSharedState(), retrieveTransientState(),
                new ExternalRequestContext.Builder().build(), singletonList(passwordCallback));

        mockErrorWhileMakingCall();

        Action result = sinchCodeCollectorCodeNode.process(context);
        Assertions.assertEquals("false", result.outcome);
    }

    private void mockVerifyCall(boolean isSuccess) {
        Mockito.when(sinchApiService.verifySynchronicallyById(any(), any(), any(), any(), any())).thenReturn(new VerificationResponseData(
                FAKE_ID, isSuccess ? VerificationStatus.SUCCESSFUL : VerificationStatus.ERROR, FAKE_METHOD.asSinchMethodType(), null, null
        ));
    }

    private void mockErrorWhileMakingCall() {
        Mockito.when(sinchApiService.verifySynchronicallyById(any(), any(), any(), any(), any())).thenAnswer(ignored -> new Exception());
    }

    private JsonValue retrieveSharedState() {
        return json(object(field(USERNAME, "demo"),
                field(SinchAuthenticationNode.INITIATED_ID_KEY, FAKE_ID),
                field(SinchAuthenticationNode.VER_METHOD_KEY, FAKE_METHOD.toString()),
                field(SinchAuthenticationNode.USER_PHONE_KEY, FAKE_NUM)));
    }

    private JsonValue retrieveTransientState() {
        return json(object(0));
    }

    private TreeContext buildTreeContext(List<? extends Callback> callbacks) {
        return new TreeContext(retrieveSharedState(), retrieveTransientState(),
                new ExternalRequestContext.Builder().build(), callbacks);
    }

    private void injectDefaultConfig() {
        Mockito.when(config.appKey()).thenReturn(FAKE_APP_KEY);
        Mockito.when(config.appSecret()).thenReturn(FAKE_APP_SECRET.toCharArray());
    }

}
