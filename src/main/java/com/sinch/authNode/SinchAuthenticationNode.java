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
import com.sinch.verification.metadata.factory.DefaultJVMMetadataFactory;
import com.sinch.verification.model.VerificationMethodType;
import com.sinch.verification.model.initiation.InitiationResponseData;
import com.sinch.verification.process.ApiCallException;
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
    static final String APP_KEY_KEY = "appHashKey";
    static final String APP_SECRET_KEY = "appSecretKey";
    static final String VER_METHOD_KEY = "verMethodKey";

    //TODO Bundle should use relative class name such as BUNDLE = SinchAuthenticationNode.class.getName();
    private static final String BUNDLE = "com/sinch/authNode/SinchAuthenticationNode";
    private static final String PLATFORM = "Forgerock";

    private final Logger logger = LoggerFactory.getLogger(SinchAuthenticationNode.class);
    private final Config config;
    private final Realm realm;
    private final CoreWrapper coreWrapper;
    private final SinchApiService sinchApiService;

    /**
     * Creates the node.
     *
     * @param config          The service config.
     * @param realm           The realm of the node.
     * @param coreWrapper     The coreWrapper instance
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
        String phoneNumber = readCallbackPhoneNumber(context);
        if (phoneNumber != null) {
            return processInitiation(context, phoneNumber);
        } else {
            phoneNumber = readProfilePhoneNumber(context.sharedState.get(IDENTITY_USERNAME_KEY).asString());
            return (phoneNumber == null) ?
                    buildInputPhoneNumberAction(bundleFromContext(context)) :
                    processInitiation(context, phoneNumber);
        }
    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[]{new OutputState(APP_KEY_KEY), new OutputState(APP_SECRET_KEY)};
    }

    private Action processInitiation(TreeContext context, String userPhone) throws NodeProcessException {
        String verificationId;
        VerificationMethodType verificationMethod = config.verificationMethod().asSinchMethodType();
        try {
            verificationId = initiateVerification(config.appKey(), config.appSecret(), formatPhoneNumber(userPhone), verificationMethod).getId();
        } catch (Exception e) {
            return askForPhoneNumberIfPossibleBasedOnException(e, bundleFromContext(context));
        }
        logger.debug("Verification initiated with id " + verificationId);
        return goToNext()
                .replaceSharedState(context.sharedState.put(INITIATED_ID_KEY, verificationId))
                .replaceSharedState(context.sharedState.put(USER_PHONE_KEY, userPhone))
                .replaceSharedState(context.sharedState.put(VER_METHOD_KEY, verificationMethod.toString()))
                //TODO Consider adding App Key and App Secret configuration options to the Collector node as well or
                // abstracting this configuration out to a service. This is transient state data is destroyed if any
                // callbacks are sent to the client. Meaning if a customer puts a node in between the Sinch Authentication
                // Node and the Sinch Code collector node, the flow will fail.
                .replaceTransientState(context.transientState.put(APP_KEY_KEY, config.appKey()))
                .replaceTransientState(context.transientState.put(APP_SECRET_KEY, config.appSecret()))
                .build();
    }

    private InitiationResponseData initiateVerification(String appKey, String appSecret, String phoneNumber, VerificationMethodType verificationMethod) {
        return sinchApiService.initiateSynchronically(
                appKey,
                appSecret,
                verificationMethod,
                phoneNumber,
                new DefaultJVMMetadataFactory(PLATFORM)
        );
    }

    private Action askForPhoneNumberIfPossibleBasedOnException(Exception exception, ResourceBundle bundle) throws NodeProcessException {
        if (exception instanceof ApiCallException && ((ApiCallException) exception).getData().getMightBePhoneFormattingError()) {
            logger.debug("Exception connected with badly formatted phone number, asking for phone number explicitly.");
            return buildInputPhoneNumberAction(bundle);
        } else {
            logger.debug("Unknown exception " + exception.getLocalizedMessage());
            throw new NodeProcessException("Unable to initiate the verification process", exception);
        }
    }

    private Action buildInputPhoneNumberAction(ResourceBundle bundle) {
        return Action.send(Arrays.asList(
                new TextOutputCallback(TextOutputCallback.INFORMATION, bundle.getString("callback.phoneNumberText")),
                new NameCallback(bundle.getString("callback.phoneNumber"))
        )).build();
    }

    private String readProfilePhoneNumber(String username) {
        try {
            String phoneProfileNumber = String.valueOf(coreWrapper.getIdentity(username, realm).getAttributes().get(config.identityPhoneNumberAttribute()));
            return isProfileNumberValid(phoneProfileNumber) ? phoneProfileNumber : null;
        } catch (Exception e) {
            logger.debug("Exception while getting user phone number from profile " + e.getLocalizedMessage());
            return null;
        }
    }

    private String readCallbackPhoneNumber(TreeContext context) {
        if (context.hasCallbacks() && context.getCallback(NameCallback.class).isPresent()) {
            return context.getCallback(NameCallback.class).get().getName();
        } else {
            return null;
        }
    }

    private boolean isProfileNumberValid(String profileNumber) {
        return !(profileNumber == null || profileNumber.equalsIgnoreCase("null")
                || profileNumber.isBlank() || profileNumber.isEmpty());
    }

    private String formatPhoneNumber(String unformatted) {
        return "+" + unformatted.replaceAll("[\\D]", "");
    }

    private ResourceBundle bundleFromContext(TreeContext context) {
        return context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
    }

    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * Application key copied from Sinch portal.
         */
        @Attribute(order = 1, validators = {RequiredValueValidator.class})
        default String appKey() {
            return "";
        }

        /**
         * Application secret copied from Sinch portal.
         */
        //TODO App Secret configuration should be type char[]. This is the plain text does not appear in the console
        @Attribute(order = 2, validators = {RequiredValueValidator.class})
        default String appSecret() {
            return "";
        }

        /**
         * Verification method used to verify user's phone number.
         */
        @Attribute(order = 3, validators = {RequiredValueValidator.class})
        default AMSupportedVerificationMethod verificationMethod() {
            return AMSupportedVerificationMethod.SMS;
        }

        /**
         * Attribute used to get user's phone number from identities store.
         */
        @Attribute(order = 4)
        default String identityPhoneNumberAttribute() {
            return DEFAULT_IDENTITY_PHONE_ATTRIBUTE;
        }
    }

}