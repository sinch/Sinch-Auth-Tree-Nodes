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
import com.sinch.authNode.service.SinchApiService;
import com.sinch.verification.model.VerificationMethodType;
import com.sinch.verification.model.initiation.InitiationResponseData;
import com.sun.identity.sm.RequiredValueValidator;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.TextOutputCallback;
import java.util.Arrays;
import java.util.ResourceBundle;

/**
 * A node that initiates the verification process for given phone number against Sinch backend.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = SinchAuthenticationNode.Config.class)
public class SinchAuthenticationNode extends SingleOutcomeNode {

    static final String IDENTITY_USERNAME_KEY = "username";
    static final String DEFAULT_IDENTITY_PHONE_ATTRIBUTE = "telephoneNumber";

    static final String USER_PHONE_KEY = "phoneNumberKey";
    static final String INITIATED_ID_KEY = "initiatedIdKey";
    static final String APP_HASH_KEY = "appHashKey";
    static final String VER_METHOD_KEY = "verMethodKey";

    private static final String BUNDLE = "com/sinch/authNode/SinchAuthenticationNode";

    private final Logger logger = LoggerFactory.getLogger(SinchAuthenticationNode.class);
    private final Config config;
    private final Realm realm;
    private final CoreWrapper coreWrapper;
    private final SinchApiService sinchApiService;

    /**
     * Create the node.
     *
     * @param config The service config.
     * @param realm  The realm of the node.
     * @param coreWrapper The coreWrapper instance
     * @param sinchApiService Service responsible for communication with Sinch Rest API Service.
     */
    @Inject
    public SinchAuthenticationNode(@Assisted Config config, @Assisted Realm realm, CoreWrapper coreWrapper, SinchApiService sinchApiService) {
        this.config = config;
        this.realm = realm;
        this.coreWrapper = coreWrapper;
        this.sinchApiService = sinchApiService;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
        String phoneNumber = readProfilePhoneNumber(context.sharedState.get(IDENTITY_USERNAME_KEY).asString());
        if (phoneNumber == null) {
            if (context.hasCallbacks() && context.getCallback(NameCallback.class).isPresent()) {
                phoneNumber = context.getCallback(NameCallback.class).get().getName();
                return processInitiation(context, phoneNumber);
            } else {
                return Action.send(Arrays.asList(
                        new TextOutputCallback(TextOutputCallback.INFORMATION, bundle.getString("callback.phoneNumberText")),
                        new NameCallback(bundle.getString("callback.phoneNumber"))
                )).build();
            }
        }
        return processInitiation(context, phoneNumber);
    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[]{new OutputState(APP_HASH_KEY)};
    }

    private Action processInitiation(TreeContext context, String userPhone) throws NodeProcessException {
        String verificationId;
        try {
            verificationId = initiateVerification(config.appHash(), formatPhoneNumber(userPhone), config.verificationMethod()).getId();
        } catch (Exception e) {
            logger.debug("Exception while initiating the verification process " + e.getLocalizedMessage());
            throw new NodeProcessException("Unable to initiate the verification process", e);
        }
        logger.debug("Verification initiated with id " + verificationId);
        return goToNext()
                .replaceSharedState(context.sharedState.put(INITIATED_ID_KEY, verificationId))
                .replaceSharedState(context.sharedState.put(USER_PHONE_KEY, userPhone))
                .replaceSharedState(context.sharedState.put(VER_METHOD_KEY, config.verificationMethod().toString()))
                .replaceTransientState(context.transientState.put(APP_HASH_KEY, config.appHash()))
                .build();
    }

    private InitiationResponseData initiateVerification(String appHash, String phoneNumber, VerificationMethodType verificationMethod) {
        return sinchApiService.initiateSynchronically(
                appHash,
                verificationMethod,
                phoneNumber
        );
    }

    private String readProfilePhoneNumber(String username) {
        try {
            return String.valueOf(coreWrapper.getIdentity(username, realm).getAttributes().get(config.identityPhoneNumberAttribute()));
        } catch (Exception e) {
            logger.debug("Exception while getting user phone number from profile " + e.getLocalizedMessage());
            return null;
        }
    }

    private String formatPhoneNumber(String unformatted) {
        return "+" + unformatted.replaceAll("[\\D]", "");
    }

    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * Application hash copied from Sinch portal.
         */
        @Attribute(order = 1, validators = {RequiredValueValidator.class})
        default String appHash() {
            return "";
        }

        /**
         * Verification method used to verify user's phone number.
         */
        @Attribute(order = 2, validators = {RequiredValueValidator.class})
        default VerificationMethodType verificationMethod() {
            return VerificationMethodType.SMS;
        }

        /**
         * Attribute used to get user's phone number from identities store.
         */
        @Attribute(order = 3)
        default String identityPhoneNumberAttribute() {
            return DEFAULT_IDENTITY_PHONE_ATTRIBUTE;
        }
    }

}