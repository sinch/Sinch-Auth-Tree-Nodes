package com.sinch.authNode.service;

import com.sinch.verification.metadata.factory.DefaultJVMMetadataFactory;
import com.sinch.verification.metadata.model.Metadata;
import com.sinch.verification.model.VerificationMethodType;
import com.sinch.verification.model.initiation.InitiationResponseData;
import com.sinch.verification.model.verification.VerificationResponseData;
import com.sinch.verification.utils.Factory;
import com.sinch.verification.utils.VerificationCallUtils;

public class SinchApiServiceImpl implements SinchApiService {

    @Override
    public InitiationResponseData initiateSynchronically(String appHash, VerificationMethodType verificationMethod, String phoneNumber, Factory<Metadata> factory) {
        return VerificationCallUtils.initiateSynchronically(appHash, verificationMethod, phoneNumber,
                null, true, null, null, factory);
    }


    @Override
    public VerificationResponseData verifySynchronicallyById(String appHash, String verificationId, String verificationCode, VerificationMethodType verificationMethod) {
        return VerificationCallUtils.verifySynchronicallyById(appHash, verificationId, verificationCode, verificationMethod);
    }

}
