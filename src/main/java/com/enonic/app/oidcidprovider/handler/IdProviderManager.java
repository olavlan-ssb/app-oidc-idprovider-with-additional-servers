package com.enonic.app.oidcidprovider.handler;

import java.io.UncheckedIOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;

import com.enonic.app.oidcidprovider.jwt.RSAAlgorithmProvider;

public class IdProviderManager
{
    private final Logger LOG = LoggerFactory.getLogger(JwtHandler.class);

    private static final int TIMEOUT_MS = 5000;

    private final Map<String, Object> idProviderConfig;

    private final RSAAlgorithmProvider algorithmProvider;

    public IdProviderManager( final Map<String, Object> idProviderConfig )
    {
        this.idProviderConfig = Objects.requireNonNull( idProviderConfig, "idProviderConfig must be set" );
        this.algorithmProvider = resolveAlgorithmProvider();
    }

    public Map<String, Object> getIdProviderConfig()
    {
        return idProviderConfig;
    }

    public Map<String, Object> getMatchingOidcServerConfig(String issuer) {
        Map<String, Object> autoLogin = (Map<String, Object>) idProviderConfig.get("autoLogin");
        LOG.debug("Autologin config: {}", autoLogin);

        List<Map<String, Object>> additionalOidcServers = (List<Map<String, Object>>) autoLogin
                .get("additionalOidcServers");
        for (Map<String, Object> oidcServerConfig : additionalOidcServers) {
            String iss = (String) oidcServerConfig.get("issuer");
            if (iss.equals(issuer)) {
                LOG.debug("Matching OIDC server config: {}", oidcServerConfig);
                return oidcServerConfig;
            }
        }
        return null;
    }

    public RSAAlgorithmProvider getAlgorithmProvider()
    {
        return algorithmProvider;
    }

    public RSAAlgorithmProvider getAlgorithmProvider(String issuer) {
        Map<String, Object> oidcServerConfig = getMatchingOidcServerConfig(issuer);
        String jwksUri = (String) oidcServerConfig.get("jwksUri");
        if (jwksUri == null) {
            return null;
        }
        final JwkProvider jwkProvider = getJwkProvider(jwksUri);
        return jwkProvider != null ? new RSAAlgorithmProvider(jwkProvider) : null;
    }

    private RSAAlgorithmProvider resolveAlgorithmProvider()
    {
            final JwkProvider jwkProvider = getJwkProvider();
            return jwkProvider != null ? new RSAAlgorithmProvider( jwkProvider ) : null;
    }

    private JwkProvider getJwkProvider()
    {
        final String jwksUri = Objects.toString( idProviderConfig.get( "jwksUri" ), null );
        if ( jwksUri == null )
        {
            return null;
        }
        final URL url;
        try
        {
            url = URI.create( jwksUri ).toURL();
        }
        catch ( MalformedURLException e )
        {
            throw new UncheckedIOException( e );
        }
        return new JwkProviderBuilder( url ).cached( true ).timeouts( TIMEOUT_MS, TIMEOUT_MS ).build();
    }

    private JwkProvider getJwkProvider(String jwksUri) {
        if (jwksUri == null) {
            return null;
        }
        final URL url;
        try {
            url = URI.create(jwksUri).toURL();
        } catch (MalformedURLException e) {
            throw new UncheckedIOException(e);
        }
        return new JwkProviderBuilder(url).cached(true).timeouts(TIMEOUT_MS, TIMEOUT_MS).build();
    }
}
