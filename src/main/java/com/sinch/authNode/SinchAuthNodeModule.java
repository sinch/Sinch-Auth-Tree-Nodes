package com.sinch.authNode;

import com.google.inject.AbstractModule;
import com.sinch.authNode.service.SinchApiService;
import com.sinch.authNode.service.SinchApiServiceImpl;

public class SinchAuthNodeModule extends AbstractModule {

    @Override
    protected void configure() {
        super.configure();
        bind(SinchApiService.class).to(SinchApiServiceImpl.class);
    }

}
