package com.sinch.authNode;


import com.google.inject.Inject;
import com.google.inject.assistedinject.Assisted;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import java.util.ArrayList;
import java.util.List;

@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = SinchCodeCollectorCodeNode.Config.class)
public class SinchCodeCollectorCodeNode extends AbstractDecisionNode {

    private final Config config;

    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * Enable whether the one-time password should be a password.
         */
        @Attribute(order = 100)
        default boolean hideCode() {
            return true;
        }

    }

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
        return collectCode(treeContext, config.hideCode());
    }

    private Action collectCode(TreeContext treeContext, boolean isHidden) {
        List<Callback> callbacks = new ArrayList<Callback>() {{
            add(new TextOutputCallback(TextOutputCallback.INFORMATION, "test"));
        }};
        if (isHidden) {
            callbacks.add(new PasswordCallback("Code", false));
        } else {
            callbacks.add(new NameCallback("Code"));
        }
        return Action.send(callbacks).build();
    }
}
