package ru.yandex_practicum.reports_api.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class CustomJwtAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(CustomJwtAuthenticationProvider.class);

    private final JwtDecoder jwtDecoder;

    public CustomJwtAuthenticationProvider(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
            String token = (String) authentication.getCredentials();
            Jwt jwt = jwtDecoder.decode(token);

            logger.info("Decoded JWT: {}", jwt.getClaims());
            logger.info("Issuer (iss): {}", jwt.getIssuer());

            return new JwtAuthenticationToken(jwt);
        } catch (Exception e) {
            logger.error("JWT authentication failed", e);
            throw e;
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
