package com.sinch.authNode;


import com.google.inject.Inject;
import com.google.inject.assistedinject.Assisted;
import com.sinch.authNode.service.SinchServiceAccessHelpers;
import com.sinch.authNode.service.SinchApiService;
import com.sinch.verification.model.VerificationMethodType;
import com.sinch.verification.model.verification.VerificationResponseData;
import com.sinch.verification.model.verification.VerificationStatus;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.AnnotatedServiceRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;

import static com.sinch.authNode.SinchAuthenticationNode.*;

/**
 * A node that performs actual verification code check against Sinch backend.
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = SinchCodeCollectorCodeNode.Config.class)
public class SinchCodeCollectorCodeNode extends AbstractDecisionNode {

    private static final String BUNDLE = SinchCodeCollectorCodeNode.class.getName();

    private final Logger logger = LoggerFactory.getLogger(SinchCodeCollectorCodeNode.class);
    private final Config config;
    private final SinchApiService sinchApiService;
    private final Realm realm;
    private final AnnotatedServiceRegistry annotatedServiceRegistry;
    private final SinchServiceAccessHelpers sinchServiceAccessHelpers = new SinchServiceAccessHelpers();

    /**
     * Creates the node
     *
     * @param config          The service config.
     * @param realm           The realm of the node.
     * @param sinchApiService Service responsible for communication with Sinch Rest API Service.
     * @param annotatedServiceRegistry Instance of AnnotatedServiceRegistry.
     */
    @Inject
    public SinchCodeCollectorCodeNode(@Assisted Config config, @Assisted Realm realm,
                                      SinchApiService sinchApiService, AnnotatedServiceRegistry annotatedServiceRegistry) {
        this.config = config;
        this.sinchApiService = sinchApiService;
        this.realm = realm;
        this.annotatedServiceRegistry = annotatedServiceRegistry;
    }

    @Override
    public Action process(TreeContext treeContext) throws NodeProcessException {
        String verificationCode = getVerificationCode(treeContext, config.isCodeHidden()).orElse(null);
        String verificationId = treeContext.getState(SinchAuthenticationNode.INITIATED_ID_KEY).asString();
        String appKey = sinchServiceAccessHelpers.getAppKeyOrThrow(annotatedServiceRegistry, realm);
        String appSecret = sinchServiceAccessHelpers.getAppSecretOrThrow(annotatedServiceRegistry, realm);
        VerificationMethodType method = VerificationMethodType.valueOf(treeContext.getState(VER_METHOD_KEY).asString());
        logger.debug("Process of SinchCodeCollectorCodeNode called. Verification code: " + verificationCode +
                " verificationId: " + verificationId + "appKey" + appKey + " method: " + method);
        if (verificationCode == null) {
            return collectCode(treeContext, config.isCodeHidden());
        } else {
            return executeCodeVerificationCheck(appKey, appSecret, verificationId, method, verificationCode);
        }
    }

    @Override
    public InputState[] getInputs() {
        return new InputState[]{new InputState(APP_KEY_KEY), new InputState(APP_SECRET_KEY)};
    }

    private Optional<String> getVerificationCode(TreeContext treeContext, boolean isCodeHidden) {
        if (isCodeHidden) {
            return treeContext.getCallback(PasswordCallback.class).map(PasswordCallback::getPassword).map(String::new);
        } else {
            return treeContext.getCallback(NameCallback.class).map(NameCallback::getName);
        }
    }

    private Action collectCode(TreeContext treeContext, boolean isHidden) {
        ResourceBundle bundle = treeContext.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());

        List<Callback> callbacks = new ArrayList<>() {{
            add(new TextOutputCallback(TextOutputCallback.INFORMATION, bundle.getString("callback.collectCodePrompt")));
        }};
        if (isHidden) {
            callbacks.add(new PasswordCallback(bundle.getString("callback.codeHint"), false));
        } else {
            callbacks.add(new NameCallback((bundle.getString("callback.codeHint"))));
        }
        return Action.send(callbacks).build();
    }

    private Action executeCodeVerificationCheck(String appKey, String appSecret, String verificationId, VerificationMethodType method, String verificationCode) {
        boolean isVerifiedSuccessfully;
        try {
            VerificationResponseData verificationResponseData = sinchApiService.verifySynchronicallyById(
                    appKey,
                    appSecret,
                    verificationId,
                    verificationCode,
                    method);
            isVerifiedSuccessfully = verificationResponseData.getStatus() == VerificationStatus.SUCCESSFUL;
        } catch (Exception e) {
            logger.debug("Exception while checking verification code " + e.getLocalizedMessage());
            isVerifiedSuccessfully = false;
        }
        return goTo(isVerifiedSuccessfully).build();
    }

    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * Enable whether the one-time password should be a password.
         */
        @Attribute(order = 1)
        default boolean isCodeHidden() {
            return true;
        }

    }
}
