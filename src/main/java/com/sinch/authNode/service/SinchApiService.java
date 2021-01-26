package com.sinch.authNode.service;

import com.sinch.verification.model.VerificationMethodType;
import com.sinch.verification.model.initiation.InitiationResponseData;

public interface SinchApiService {

    InitiationResponseData initiateSynchronically(String appHash, VerificationMethodType verificationMethod, String phoneNumber);
}
