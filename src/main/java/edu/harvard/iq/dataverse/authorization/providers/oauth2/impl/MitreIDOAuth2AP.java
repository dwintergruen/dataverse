package edu.harvard.iq.dataverse.authorization.providers.oauth2.impl;

import com.github.scribejava.core.builder.api.BaseApi;
import edu.harvard.iq.dataverse.authorization.AuthenticatedUserDisplayInfo;
import edu.harvard.iq.dataverse.authorization.providers.oauth2.AbstractOAuth2AuthenticationProvider;
import edu.harvard.iq.dataverse.util.BundleUtil;
import java.io.StringReader;
import java.util.UUID;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

/**
 *
 * @author michael
 */


public class MitreIDOAuth2AP extends AbstractOAuth2AuthenticationProvider {
    public static final String PROVIDER_ID = "mitreid";    
    public MitreIDOAuth2AP(String aClientId, String aClientSecret) {
        id = "mitreid";
        title = BundleUtil.getStringFromBundle("auth.providers.title.mitreid");
        clientId = aClientId;
        clientSecret = aClientSecret;
        scope =  "openid profile email";
        baseUserEndpoint = "https://id.mpiwg-berlin.mpg.de/openid/userinfo";
    }
   
    @Override
    public BaseApi getApiInstance() {
        return MitreIDApi.instance();
    }

    @Override
    protected ParsedUserResponse parseUserResponse(String responseBody) {
        try ( StringReader rdr = new StringReader(responseBody);
              JsonReader jrdr = Json.createReader(rdr) )  {
            JsonObject response = jrdr.readObject();
            
            AuthenticatedUserDisplayInfo displayInfo = new AuthenticatedUserDisplayInfo(
                    response.getString("given_name",""),
                    response.getString("family_name",""),
                    response.getString("email",""),
                    "",
                    ""
            );
            String persistentUserId = response.getString("sub");
            String username = response.getString("email");
            if ( username != null ) {
                username = username.split("@")[0].trim();
            } else {
                // compose a username from given and family names
                username = response.getString("given_name","") + "."
                           + response.getString("family_name","");
                username = username.trim();
                if ( username.isEmpty() ) {
                    username = UUID.randomUUID().toString();
                } else {
                    username = username.replaceAll(" ", "-");
                }
            }
            return new ParsedUserResponse(displayInfo, persistentUserId, username);
        }
    }

    @Override
    public boolean isDisplayIdentifier() {
        return false;
    }
    
}
