package edu.harvard.iq.dataverse.authorization.providers.oauth2.impl;

import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.extractors.OAuth2AccessTokenJsonExtractor;
import com.github.scribejava.core.extractors.TokenExtractor;
import com.github.scribejava.core.model.OAuth2AccessToken;

/**
 * Adaptor for ORCiD OAuth identity Provider.
 * @author michael
 */
public class MitreIDApi extends DefaultApi20 {
    
   
    
    private static class InstanceHolder {
        private static final MitreIDApi INSTANCE =
                new MitreIDApi("https://id.mpiwg-berlin.mpg.de/openid/token",
                             "https://id.mpiwg-berlin.mpg.de/openid/authorize");
    }
    
    public static MitreIDApi instance() {
        return  InstanceHolder.INSTANCE;
    }
    
    private final String accessTokenEndpoint;
    private final String authorizationBaseUrl;

    protected MitreIDApi(String accessTokenEndpoint, String authorizationBaseUrl) {
        this.accessTokenEndpoint = accessTokenEndpoint;
        this.authorizationBaseUrl = authorizationBaseUrl;
    }
    
    @Override
    public String getAccessTokenEndpoint() {
        return accessTokenEndpoint;
    }

    @Override
    protected String getAuthorizationBaseUrl() {
        return authorizationBaseUrl;
    }



    @Override
    public TokenExtractor<OAuth2AccessToken> getAccessTokenExtractor() {
        return OAuth2AccessTokenJsonExtractor.instance();
    }
    
}
