package com.sinch.authNode;


import com.google.inject.Inject;
import com.google.inject.assistedinject.Assisted;
import com.sinch.authNode.service.SinchApiService;
import com.sinch.verification.model.VerificationMethodType;
import com.sinch.verification.model.verification.VerificationResponseData;
import com.sinch.verification.model.verification.VerificationStatus;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
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

    private static final String BUNDLE = "com/sinch/authNode/SinchCodeCollectorCodeNode";

    private final Logger logger = LoggerFactory.getLogger(SinchCodeCollectorCodeNode.class);
    private final Config config;
    private final SinchApiService sinchApiService;

    /**
     * Creates the node
     *
     * @param config          The service config.
     * @param sinchApiService Service responsible for communication with Sinch Rest API Service.
     */
    @Inject
    public SinchCodeCollectorCodeNode(@Assisted Config config, SinchApiService sinchApiService) {
        this.config = config;
        this.sinchApiService = sinchApiService;
    }

    @Override
    public Action process(TreeContext treeContext) {
        String verificationCode = getVerificationCode(treeContext, config.isCodeHidden()).orElse(null);
        String verificationId = treeContext.getState(SinchAuthenticationNode.INITIATED_ID_KEY).asString();
        String appKey = treeContext.getState(APP_KEY_KEY).asString();
        String appSecret = treeContext.getState(APP_SECRET_KEY).asString();
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
