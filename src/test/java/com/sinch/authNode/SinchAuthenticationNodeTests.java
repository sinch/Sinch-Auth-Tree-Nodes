package com.sinch.authNode;

import com.google.common.collect.ImmutableMap;
import com.iplanet.sso.SSOException;
import com.sinch.authNode.service.SinchApiService;
import com.sinch.authNode.service.SinchAuxService;
import com.sinch.verification.metadata.factory.DefaultJVMMetadataFactory;
import com.sinch.verification.model.ApiErrorData;
import com.sinch.verification.model.VerificationMethodType;
import com.sinch.verification.model.initiation.InitiationResponseData;
import com.sinch.verification.model.initiation.methods.AutoInitializationResponseDetails;
import com.sinch.verification.process.ApiCallException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.AnnotatedServiceRegistry;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.TextOutputCallback;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.sinch.authNode.SinchAuthenticationNode.INITIATED_ID_KEY;
import static com.sinch.authNode.TestConstants.*;
import static java.util.Collections.emptyList;
import static org.forgerock.json.JsonValue.*;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.mockito.ArgumentMatchers.*;

public class SinchAuthenticationNodeTests {

    @Mock
    private SinchAuthenticationNode.Config config;

    @Mock
    private Realm realm;

    @Mock
    private CoreWrapper coreWrapper;

    @Mock
    private AMIdentity mockUser;

    @Mock
    private SinchApiService sinchApiService;

    @Mock
    private AnnotatedServiceRegistry annotatedServiceRegistry;

    @Mock
    private SinchAuxService sinchAuxService;

    private SinchAuthenticationNode sinchAuthenticationNode;
    private TreeContext context;

    private ArgumentMatcher<DefaultJVMMetadataFactory> factoryMatcher;

    @BeforeEach
    public void setup() throws Exception {
        MockitoAnnotations.openMocks(this).close();
        factoryMatcher = (argument -> argument.getPlatform().equals("Forgerock"));
        context = buildThreeContext(emptyList());
        sinchAuthenticationNode = new SinchAuthenticationNode(config, realm, coreWrapper, sinchApiService, annotatedServiceRegistry);
    }

    private JsonValue retrieveSharedState() {
        return json(object(field(USERNAME, "demo")));
    }

    @Test
    public void testProcessActionWhenNoUserPhoneInProfile() throws NodeProcessException {
        Action result = sinchAuthenticationNode.process(context);
        Assertions.assertEquals(2, result.callbacks.size());
        Callback prompt = result.callbacks.get(0);
        Callback enterPhone = result.callbacks.get(1);
        Assertions.assertTrue(prompt instanceof TextOutputCallback);
        Assertions.assertTrue(enterPhone instanceof NameCallback);
    }

    @Test
    public void testProcessWhenPhoneNumberInProfile() throws IdRepoException, SSOException, NodeProcessException {
        injectDefaultConfig();
        mockSuccessfulRestApiCall();
        Map attributeMap = ImmutableMap.of(config.identityPhoneNumberAttribute(), FAKE_NUM);
        Mockito.when(mockUser.getAttributes()).thenReturn(attributeMap);
        Mockito.when(coreWrapper.getIdentity(anyString(), any(Realm.class))).thenReturn(mockUser);

        Action result = sinchAuthenticationNode.process(context);
        Mockito.verify(sinchApiService).initiateSynchronically(eq(FAKE_APP_KEY), eq(FAKE_APP_SECRET), eq(VerificationMethodType.SMS), eq(FAKE_NUM), argThat(factoryMatcher));
        Assert.assertEquals(result.outcome, "outcome");
        verifyOutcomeSharedState(result);
    }

    @Test
    public void testProcessWhenMalformedProfileNumber() throws NodeProcessException, IdRepoException, SSOException {
        injectDefaultConfig();
        mockSuccessfulRestApiCall();

        Map attributeMap = ImmutableMap.of(config.identityPhoneNumberAttribute(), "");
        Mockito.when(mockUser.getAttributes()).thenReturn(attributeMap);
        Mockito.when(coreWrapper.getIdentity(anyString(), any(Realm.class))).thenReturn(mockUser);

        verifyProcessProducesExplicitPhoneNumberInputRequest();
    }

    @Test
    public void testProcessWhenApiReturnsPhoneNumberFormattingError() throws NodeProcessException {
        injectDefaultConfig();
        mockExceptionWhileMakingRestCall(
                new ApiCallException(new ApiErrorData(ApiErrorData.ErrorCodes.ParameterValidation, "", ""))
        );
        verifyProcessProducesExplicitPhoneNumberInputRequest();
    }

    @Test
    public void testProcessWhenNumberInCallback() throws NodeProcessException {
        injectDefaultConfig();
        mockSuccessfulRestApiCall();
        NameCallback phoneNumberCallback = new NameCallback("ignored");
        phoneNumberCallback.setName(FAKE_NUM);
        List<Callback> callbacks = Arrays.asList(
                new TextOutputCallback(TextOutputCallback.INFORMATION, "ignored"),
                phoneNumberCallback);
        context = new TreeContext(retrieveSharedState(), json(object()),
                new ExternalRequestContext.Builder().build(), callbacks
                , Optional.of("mockUserId"));

        Action result = sinchAuthenticationNode.process(context);
        Mockito.verify(sinchApiService).initiateSynchronically(eq(FAKE_APP_KEY), eq(FAKE_APP_SECRET), eq(VerificationMethodType.SMS), eq(FAKE_NUM), argThat(factoryMatcher));
        Assert.assertEquals(result.outcome, "outcome");
        verifyOutcomeSharedState(result);
    }

    @Test
    public void testProcessFailureWhenExceptionWhileMakingCallToSinchApi() throws IdRepoException, SSOException {
        injectDefaultConfig();
        mockExceptionWhileMakingRestCall(new Exception());
        Map attributeMap = ImmutableMap.of(config.identityPhoneNumberAttribute(), FAKE_NUM);
        Mockito.when(mockUser.getAttributes()).thenReturn(attributeMap);
        Mockito.when(coreWrapper.getIdentity(anyString(), any(Realm.class))).thenReturn(mockUser);
        Assertions.assertThrows(NodeProcessException.class, () -> sinchAuthenticationNode.process(context));
    }

    @Test
    public void testPhoneNumberFormattingWithWhitespaces() throws NodeProcessException {
        injectDefaultConfig();
        mockSuccessfulRestApiCall();
        NameCallback phoneNumberCallback = new NameCallback("ignored");
        phoneNumberCallback.setName("+48 123 456 789");
        List<Callback> callbacks = Arrays.asList(
                new TextOutputCallback(TextOutputCallback.INFORMATION, "ignored"),
                phoneNumberCallback);

        sinchAuthenticationNode.process(buildThreeContext(callbacks));
        Mockito.verify(sinchApiService).initiateSynchronically(eq(FAKE_APP_KEY), eq(FAKE_APP_SECRET), eq(VerificationMethodType.SMS), eq("+48123456789"), argThat(factoryMatcher));
    }

    @Test
    public void testPhoneNumberFormattingWithoutLeadingPlus() throws NodeProcessException {
        injectDefaultConfig();
        mockSuccessfulRestApiCall();
        NameCallback phoneNumberCallback = new NameCallback("ignored");
        phoneNumberCallback.setName("48123456789");
        List<Callback> callbacks = Arrays.asList(
                new TextOutputCallback(TextOutputCallback.INFORMATION, "ignored"),
                phoneNumberCallback);

        sinchAuthenticationNode.process(buildThreeContext(callbacks));
        Mockito.verify(sinchApiService).initiateSynchronically(eq(FAKE_APP_KEY), eq(FAKE_APP_SECRET), eq(VerificationMethodType.SMS), eq("+48123456789"), argThat(factoryMatcher));
    }

    private void injectDefaultConfig() {
        Mockito.when(config.identityPhoneNumberAttribute()).thenReturn("telephoneNumber");
//        Mockito.when(config.appKey()).thenReturn(FAKE_APP_KEY);
//        Mockito.when(config.appSecret()).thenReturn(FAKE_APP_SECRET);
        Mockito.when(config.verificationMethod()).thenReturn(FAKE_METHOD);
    }

    private void mockSuccessfulRestApiCall() {
        Mockito.when(sinchApiService.initiateSynchronically(anyString(), anyString(), any(), anyString(), any()))
                .thenReturn(
                        new InitiationResponseData(FAKE_ID, new AutoInitializationResponseDetails(FAKE_ID, emptyList()), null,
                                null, null, null, VerificationMethodType.SMS, null)
                );
    }

    private void mockExceptionWhileMakingRestCall(Exception exception) {
        Mockito.when(sinchApiService.initiateSynchronically(anyString(), anyString(), any(), anyString(), any()))
                .thenAnswer(ignored -> {
                    throw exception;
                });
    }

    private void verifyProcessProducesExplicitPhoneNumberInputRequest() throws NodeProcessException {
        Action result = sinchAuthenticationNode.process(context);
        Assertions.assertEquals(2, result.callbacks.size());
        Callback prompt = result.callbacks.get(0);
        Callback enterPhone = result.callbacks.get(1);
        Assertions.assertTrue(prompt instanceof TextOutputCallback);
        Assertions.assertTrue(enterPhone instanceof NameCallback);
    }

    private void verifyOutcomeSharedState(Action action) {
        Assertions.assertEquals(FAKE_ID, action.sharedState.get(INITIATED_ID_KEY).asString());
        Assertions.assertEquals(FAKE_METHOD.toString(), action.sharedState.get(SinchAuthenticationNode.VER_METHOD_KEY).asString());
        Assertions.assertEquals(FAKE_NUM, action.sharedState.get(SinchAuthenticationNode.USER_PHONE_KEY).asString());
        Assertions.assertEquals(FAKE_APP_KEY, action.transientState.get(SinchAuthenticationNode.APP_KEY_KEY).asString());
    }

    private TreeContext buildThreeContext(List<Callback> callbacks) {
        return new TreeContext(retrieveSharedState(), json(object()),
                new ExternalRequestContext.Builder().build(), callbacks
                , Optional.of("mockUserId"));
    }

}
