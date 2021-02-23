package com.sinch.authNode.service;

import com.sinch.verification.metadata.model.Metadata;
import com.sinch.verification.model.VerificationMethodType;
import com.sinch.verification.model.initiation.InitiationResponseData;
import com.sinch.verification.model.verification.VerificationResponseData;
import com.sinch.verification.utils.Factory;

public interface SinchApiService {

    InitiationResponseData initiateSynchronically(String appHash, String appSecret, VerificationMethodType verificationMethod, String phoneNumber,
                                                  Factory<Metadata> metadataFactory);

    VerificationResponseData verifySynchronicallyById(String appHash, String appSecret, String verificationId, String verificationCode, VerificationMethodType verificationMethodType);

}
