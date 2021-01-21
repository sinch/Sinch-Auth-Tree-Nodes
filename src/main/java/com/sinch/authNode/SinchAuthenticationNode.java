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
import com.sinch.verification.utils.VerificationCallUtils;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.sm.RequiredValueValidator;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.realms.Realm;
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
public class SinchAuthenticationNode extends SingleOutcomeNode {

    static final String PROFILE_PHONE_KEY = "telephoneNumber";
    static final String USERNAME_KEY = "username";

    static final String USER_PHONE_KEY = "phoneNumber";
    static final String INITIATED_ID_KEY = "initiatedId";
    static final String APP_HASH_KEY = "appHash";
    static final String VER_METHOD_KEY = "verMethodKey";

    private static final String BUNDLE = "com/sinch/authNode/SinchAuthenticationNode";

    private final Logger logger = LoggerFactory.getLogger(SinchAuthenticationNode.class);
    private final Config config;
    private final Realm realm;

    /**
     * Create the node.
     *
     * @param config The service config.
     * @param realm The realm of the node.
     */
    @Inject
    public SinchAuthenticationNode(@Assisted Config config, @Assisted Realm realm) {
        this.config = config;
        this.realm = realm;
    }

    @Override
    public Action process(TreeContext context) {
        logger.debug("Process function of SinchAuthenticationNode called with sharedState " + context.sharedState);
        ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
        String phoneNumber = readProfilePhoneNumber(context.sharedState.get(USERNAME_KEY).asString());
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

    private Action processInitiation(TreeContext context, String userPhone) {
        String verificationId = initiateVerification(config.appHash(), formatPhoneNumber(userPhone), config.verificationMethod()).getId();
        logger.debug("Verification initiated with id " + verificationId);
        return goToNext()
                .replaceSharedState(context.sharedState.put(INITIATED_ID_KEY, verificationId))
                .replaceSharedState(context.sharedState.put(USER_PHONE_KEY, userPhone))
                .replaceSharedState(context.sharedState.put(SinchCodeCollectorCodeNode.VERIFICATION_METHOD_KEY, config.verificationMethod()))
                .replaceSharedState(context.sharedState.put(APP_HASH_KEY, config.appHash()))
                .replaceSharedState(context.sharedState.put(VER_METHOD_KEY, config.verificationMethod().toString()))
                .build();
    }

    private InitiationResponseData initiateVerification(String appHash, String phoneNumber, VerificationMethodType verificationMethod) {
        return VerificationCallUtils.initiateSynchronically(
                appHash,
                verificationMethod,
                phoneNumber
        );
    }

    private String readProfilePhoneNumber(String username) {
        try {
            return String.valueOf(IdUtils.getIdentity(username, realm).getAttributes().get(PROFILE_PHONE_KEY));
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