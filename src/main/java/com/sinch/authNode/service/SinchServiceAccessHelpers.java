package com.sinch.authNode.service;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.AnnotatedServiceRegistry;

public class SinchServiceAccessHelpers {

    public String getAppKeyOrThrow(AnnotatedServiceRegistry annotatedServiceRegistry, Realm realm) throws NodeProcessException {
        try {
            SinchAuxService sinchAuxService = annotatedServiceRegistry.getRealmSingleton(SinchAuxService.class, realm).get();
            return sinchAuxService.appKey();
        } catch (Exception e) {
            throw new NodeProcessException("Error while getting application key", e);
        }
    }

    public String getAppSecretOrThrow(AnnotatedServiceRegistry annotatedServiceRegistry, Realm realm) throws NodeProcessException {
        try {
            SinchAuxService sinchAuxService = annotatedServiceRegistry.getRealmSingleton(SinchAuxService.class, realm).get();
            return sinchAuxService.appSecret();
        } catch (Exception e) {
            throw new NodeProcessException("Error while getting application secret", e);
        }
    }
}
