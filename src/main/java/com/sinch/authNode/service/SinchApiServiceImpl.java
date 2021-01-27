package com.sinch.authNode.service;

import com.sinch.verification.model.VerificationMethodType;
import com.sinch.verification.model.initiation.InitiationResponseData;
import com.sinch.verification.model.verification.VerificationResponseData;
import com.sinch.verification.utils.VerificationCallUtils;

public class SinchApiServiceImpl implements SinchApiService {

    @Override
    public InitiationResponseData initiateSynchronically(String appHash, VerificationMethodType verificationMethod, String phoneNumber) {
        return VerificationCallUtils.initiateSynchronically(appHash, verificationMethod, phoneNumber);
    }


    @Override
    public VerificationResponseData verifySynchronicallyById(String appHash, String verificationId, String verificationCode, VerificationMethodType verificationMethod) {
        return VerificationCallUtils.verifySynchronicallyById(appHash, verificationId, verificationCode, verificationMethod);
    }

}
