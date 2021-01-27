package com.sinch.authNode.service;

import com.sinch.verification.model.VerificationMethodType;
import com.sinch.verification.model.initiation.InitiationResponseData;
import com.sinch.verification.model.verification.VerificationResponseData;

public interface SinchApiService {

    InitiationResponseData initiateSynchronically(String appHash, VerificationMethodType verificationMethod, String phoneNumber);

    VerificationResponseData verifySynchronicallyById(String appHash, String verificationId, String verificationCode, VerificationMethodType verificationMethodType);

}
