package com.sinch.authNode.service;

import com.sinch.verification.metadata.model.Metadata;
import com.sinch.verification.model.VerificationMethodType;
import com.sinch.verification.model.initiation.InitiationResponseData;
import com.sinch.verification.model.verification.VerificationResponseData;
import com.sinch.verification.network.auth.ApplicationAuthorizationMethod;
import com.sinch.verification.utils.Factory;
import com.sinch.verification.utils.VerificationCallUtils;

public class SinchApiServiceImpl implements SinchApiService {

    @Override
    public InitiationResponseData initiateSynchronically(String appHash, String appSecret, VerificationMethodType verificationMethod,
                                                         String phoneNumber, Factory<Metadata> metadataFactory) {
        return VerificationCallUtils.initiateSynchronically(new ApplicationAuthorizationMethod(appHash, appSecret),
                verificationMethod, phoneNumber, null, true, null, null, metadataFactory);
    }

    @Override
    public VerificationResponseData verifySynchronicallyById(String appHash, String appSecret, String verificationId, String verificationCode,
                                                             VerificationMethodType verificationMethodType) {
        return VerificationCallUtils.verifySynchronicallyById(new ApplicationAuthorizationMethod(appHash, appSecret),
                verificationId, verificationCode, verificationMethodType);
    }
}
