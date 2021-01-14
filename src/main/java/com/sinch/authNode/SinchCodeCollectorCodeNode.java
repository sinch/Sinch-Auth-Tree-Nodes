package com.sinch.authNode;


import com.google.inject.Inject;
import com.google.inject.assistedinject.Assisted;
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

@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = SinchCodeCollectorCodeNode.Config.class)
public class SinchCodeCollectorCodeNode extends AbstractDecisionNode {

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
    public Action process(TreeContext treeContext) throws NodeProcessException {
        logger.debug("Process called of SinchCodeCollectorCodeNode");
        String verificationCode = getVerificationCode(treeContext, config.isCodeHidden()).orElse(null);
        //TODO Obtain the initiated verification ID.
        if (verificationCode == null) {
            return collectCode(treeContext, config.isCodeHidden());
        } else {
            return checkVerificationCode(verificationCode);
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

    private Action checkVerificationCode(String verificationCode) {
        return goTo(true).build();
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
