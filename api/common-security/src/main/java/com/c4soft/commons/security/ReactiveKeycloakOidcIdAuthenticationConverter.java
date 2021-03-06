package com.c4soft.commons.security;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdAuthenticationToken;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdBuilder;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Component
public class ReactiveKeycloakOidcIdAuthenticationConverter implements Converter<Jwt, Mono<OidcIdAuthenticationToken>> {

    private final KeycloakAuthoritiesConverter authoritiesConverter;

    @Autowired
    public ReactiveKeycloakOidcIdAuthenticationConverter(KeycloakAuthoritiesConverter authoritiesConverter) {
        this.authoritiesConverter = authoritiesConverter;
    }

    @Override
    public Mono<OidcIdAuthenticationToken> convert(Jwt jwt) {
        final var token = new OidcIdBuilder(jwt.getClaims()).build();
        return authoritiesConverter.convert(jwt).collectList().map(authorities -> new OidcIdAuthenticationToken(token, authorities));
    }

    @Component
    static class KeycloakAuthoritiesConverter implements Converter<Jwt, Flux<GrantedAuthority>> {

        @Value("${com.c4-soft.security.oauth2.client-id}")
        String clientId;

        @Override
        @NonNull
        public Flux<GrantedAuthority> convert(Jwt jwt) {
            final var roles =
                    Optional.ofNullable((JSONObject) jwt.getClaims().get("resource_access"))
                            .flatMap(resourceAccess -> Optional.ofNullable((JSONObject) resourceAccess.get(clientId)))
                            .flatMap(clientResourceAccess -> Optional.ofNullable((JSONArray) clientResourceAccess.get("roles")))
                            .orElse(new JSONArray());

            return Flux.fromStream(roles.stream().map(Object::toString).map(SimpleGrantedAuthority::new));
        }

    }
}