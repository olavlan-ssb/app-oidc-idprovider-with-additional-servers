package com.enonic.app.oidcidprovider.handler;

import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.enonic.app.oidcidprovider.jwt.RSAAlgorithmProvider;
import com.enonic.app.oidcidprovider.mapper.MapMapper;
import com.enonic.xp.script.bean.BeanContext;
import com.enonic.xp.script.bean.ScriptBean;

public class JwtHandler
    implements ScriptBean
{
    private final Logger LOG = LoggerFactory.getLogger( JwtHandler.class );

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Supplier<IdProviderConfigService> idProviderConfigServiceSupplier;

    @Override
    public void initialize( final BeanContext context )
    {
        this.idProviderConfigServiceSupplier = context.getService( IdProviderConfigService.class );
    }

    public Object validateTokenAndGetPayload(final String jwtToken, final String idProviderName,
            List<String> allowedAudience)
    {
        if ( jwtToken == null )
        {
            return null;
        }

        try
        {
            DecodedJWT decodedJwt = JWT.decode( jwtToken );

            final String issuer = decodedJwt.getIssuer();
            if (issuer == null) {
                return null;
            }

            IdProviderManager idProviderManager = idProviderConfigServiceSupplier.get()
                    .getIdProviderManager(idProviderName);
            Map<String, Object> idProviderConfig = idProviderManager.getIdProviderConfig();

            String mainIssuer = (String) idProviderConfig.get("issuer");
            if (!issuer.equals(mainIssuer)) {
                Map<String, Object> oidcServerConfig = idProviderManager.getMatchingOidcServerConfig(issuer);
                allowedAudience = (List<String>) oidcServerConfig.get("allowedAudience");
            }

            if ( !allowedAudience.isEmpty() && decodedJwt.getAudience() != null )
            {
                Set<String> intersection =
                    decodedJwt.getAudience().stream().distinct().filter( allowedAudience::contains ).collect( Collectors.toSet() );
                if ( intersection.isEmpty() )
                {
                    LOG.debug( "Invalid audience: {}", decodedJwt.getAudience() );
                    return null;
                }
            }

            RSAAlgorithmProvider rsaAlgorithmProvider = idProviderManager.getAlgorithmProvider(issuer);

            JWT.require( rsaAlgorithmProvider.getAlgorithm( decodedJwt.getAlgorithm() ) ).acceptLeeway( 1 ).   // 1 sec for nbf and iat
                build().verify( decodedJwt );

            return new MapMapper( getPayload( decodedJwt.getPayload() ) );
        }
        catch ( Exception e )
        {
            LOG.debug( "Failed to validate token: {}", e.getMessage() );
            return null;
        }
    }

    private static Map<String, Object> getPayload( String base64Payload )
        throws IOException
    {
        return MAPPER.readValue( Base64.getDecoder().decode( base64Payload ), Map.class );
    }
}
