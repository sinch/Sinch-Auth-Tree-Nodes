package com.sinch.authNode.service;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.annotations.sm.Config;

@Config(scope = Config.Scope.REALM)
public interface SinchAuxService {

    /**
     * Application key copied from Sinch portal.
     */
    @Attribute(order = 1)
    default String appKey() {
        return "";
    }

    /**
     * Application secret copied from Sinch portal.
     */
    @Attribute(order = 2)
    default String appSecret() {
        return "";
    }

}

