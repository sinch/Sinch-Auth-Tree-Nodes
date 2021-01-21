package com.sinch.authNode;


import com.google.inject.Inject;
import com.google.inject.assistedinject.Assisted;
import com.sinch.verification.model.VerificationMethodType;
import com.sinch.verification.model.verification.VerificationResponseData;
import com.sinch.verification.model.verification.VerificationStatus;
import com.sinch.verification.utils.VerificationCallUtils;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.TreeContext;
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

@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = SinchCodeCollectorCodeNode.Config.class)
public class SinchCodeCollectorCodeNode extends AbstractDecisionNode {

    static final String VERIFICATION_METHOD_KEY = "verMethodKey";
    private static final String BUNDLE = "com/sinch/authNode/SinchCodeCollectorCodeNode";
    private final Logger logger = LoggerFactory.getLogger(SinchCodeCollectorCodeNode.class);
    private final Config config;

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public SinchCodeCollectorCodeNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext treeContext) {
        String verificationCode = getVerificationCode(treeContext, config.isCodeHidden()).orElse(null);
        String verificationId = treeContext.sharedState.get(SinchAuthenticationNode.INITIATED_ID_KEY).asString();
        String appHash = treeContext.sharedState.get(SinchAuthenticationNode.APP_HASH_KEY).asString();
        VerificationMethodType method = VerificationMethodType.valueOf(treeContext.sharedState.get(SinchAuthenticationNode.VER_METHOD_KEY).asString());
        logger.debug("Process SinchCodeCollectorCodeNode called verificationId: " + verificationId +
                " verification code: " + verificationCode + " appHash: " + appHash + " verification method: " + method);
        if (verificationCode == null) {
            return collectCode(treeContext, config.isCodeHidden());
        } else {
            return checkVerificationCode(appHash, verificationId, method, verificationCode);
        }
    }

    private Optional<String> getVerificationCode(TreeContext treeContext, boolean isCodeHiden) {
        if (isCodeHiden) {
            return treeContext.getCallback(PasswordCallback.class).map(PasswordCallback::getPassword).map(String::new);
        } else {
            return treeContext.getCallback(NameCallback.class).map(NameCallback::getName);
        }
    }

    private Action collectCode(TreeContext treeContext, boolean isHidden) {
        ResourceBundle bundle = treeContext.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());

        List<Callback> callbacks = new ArrayList<Callback>() {{
            add(new TextOutputCallback(TextOutputCallback.INFORMATION, bundle.getString("callback.collectCodePrompt")));
        }};
        if (isHidden) {
            callbacks.add(new PasswordCallback(bundle.getString("callback.codeHint"), false));
        } else {
            callbacks.add(new NameCallback((bundle.getString("callback.codeHint"))));
        }
        return Action.send(callbacks).build();
    }

    private Action checkVerificationCode(String appHash, String verificationId, VerificationMethodType method, String verificationCode) {
        boolean isVerifiedSuccessfully;
        try {
            VerificationResponseData verificationResponseData = VerificationCallUtils.verifySynchronicallyById(
                    appHash,
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
