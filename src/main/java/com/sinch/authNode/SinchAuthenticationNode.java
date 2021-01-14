/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */


package com.sinch.authNode;

import com.google.inject.assistedinject.Assisted;
import com.sinch.verification.model.VerificationMethodType;
import com.sinch.verification.model.initiation.InitiationResponseData;
import com.sinch.verification.network.auth.AppKeyAuthorizationMethod;
import com.sinch.verification.process.config.VerificationMethodConfig;
import com.sinch.verification.process.listener.InitiationListener;
import com.sinch.verification.process.method.VerificationMethod;
import com.sun.identity.sm.RequiredValueValidator;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.authentication.callbacks.PollingWaitCallback;
import org.forgerock.openam.core.CoreWrapper;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.TextOutputCallback;
import java.util.Arrays;
import java.util.ResourceBundle;

/**
 * A node that checks to see if zero-page login headers have specified username and shared key
 * for this request.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = SinchAuthenticationNode.Config.class)
public class SinchAuthenticationNode extends SingleOutcomeNode implements InitiationListener {

    static final String USER_PHONE_KEY = "phoneNumber";
    static final String INITIATED_ID_KEY = "initiatedId";

    private static final String BUNDLE = "com/sinch/authNode/SinchAuthenticationNode";

    private final Logger logger = LoggerFactory.getLogger(SinchAuthenticationNode.class);
    private final Config config;

    private String initiatedVerificationId = null;

    /**
     * Create the node.
     *
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public SinchAuthenticationNode(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        logger.debug("SinchAuthenticationNode initiated");
    }

    @Override
    public Action process(TreeContext context) {
        logger.debug("Process function of SinchAuthenticationNode called");
        ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
        String userPhone = context.sharedState.get(USER_PHONE_KEY).asString();
        if (userPhone == null) {
            if (context.hasCallbacks() && context.getCallback(NameCallback.class).isPresent()) {
                userPhone = context.getCallback(NameCallback.class).get().getName();
                initiateVerification(config.appHash(), userPhone, config.verificationMethod());
                logger.debug("User phone is " + userPhone);
                return processInitiation(context, userPhone);
            } else {
                return Action.send(Arrays.asList(
                        new TextOutputCallback(TextOutputCallback.INFORMATION, bundle.getString("callback.phoneNumberText")),
                        new NameCallback(bundle.getString("callback.phoneNumber"))
                )).build();
            }
        }
        return processInitiation(context, userPhone);
    }

    private Action processInitiation(TreeContext context, String userPhone) {
        if (initiatedVerificationId != null) {
            logger.debug("Initiated verification id is " + initiatedVerificationId);
            return goToNext()
                    .replaceSharedState(context.sharedState.put(INITIATED_ID_KEY, initiatedVerificationId))
                    .build();
        } else {
            logger.debug("Waiting for initiation response");
            return Action.send(
                    new PollingWaitCallback.PollingWaitCallbackBuilder()
                            .withWaitTime(String.valueOf(1000))
                            .build())
                    .replaceSharedState(context.sharedState.put(USER_PHONE_KEY, userPhone))
                    .build();
        }
    }

    private void initiateVerification(String appHash, String phoneNumber, VerificationMethodType verificationMethod) {
        VerificationMethodConfig verificationMethodConfig = VerificationMethodConfig.Builder.getInstance()
                .authorizationMethod(new AppKeyAuthorizationMethod(appHash))
                .verificationMethod(verificationMethod)
                .number(phoneNumber)
                .build();

        VerificationMethod.Builder.getInstance()
                .verificationConfig(verificationMethodConfig)
                .initiationListener(this)
                .build()
                .initiate();
    }

    @Override
    public void onInitializationFailed(@NotNull Throwable throwable) {
        logger.debug("Error while receiving response " + throwable.getLocalizedMessage());
    }

    @Override
    public void onInitiated(@NotNull InitiationResponseData initiationResponseData) {
        logger.debug("Response received id is " + initiationResponseData.getId());
        initiatedVerificationId = initiationResponseData.getId();
    }

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 1, validators = {RequiredValueValidator.class})
        default String appHash() {
            return "";
        }

        @Attribute(order = 2, validators = {RequiredValueValidator.class})
        default VerificationMethodType verificationMethod() {
            return VerificationMethodType.SMS;
        }
    }

}