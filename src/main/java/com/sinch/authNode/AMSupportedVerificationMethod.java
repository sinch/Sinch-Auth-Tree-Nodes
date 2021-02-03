package com.sinch.authNode;

import com.sinch.verification.model.VerificationMethodType;

/**
 * Enum representing currently supported verification methods (SMS, Flashcalls and Callout). This class is used
 * as SinchAuthenticationNode property, so other methods available inside the SDK are not visible inside AM authentication
 * tree builder.
 */
public enum AMSupportedVerificationMethod {

    SMS,
    FLASHCALL,
    CALLOUT;

    public VerificationMethodType asSinchMethodType() {
        switch (this) {
            case SMS:
                return VerificationMethodType.SMS;
            case CALLOUT:
                return VerificationMethodType.CALLOUT;
            case FLASHCALL:
                return VerificationMethodType.FLASHCALL;
        }
        throw new RuntimeException("Mapping not defined for " + this);
    }
}
