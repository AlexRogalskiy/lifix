package com.c4soft.commons.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.reactive.config.CorsRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class WebSecurityConfig {

    @Value("${com.c4-soft.security.cors-path}")
    String corsPath;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http, ReactiveKeycloakOidcIdAuthenticationConverter authenticationConverter) {

        http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter);

        // @formatter:off
        http.anonymous().and()
            .cors().and()
            .csrf().disable()
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .exceptionHandling()
                .accessDeniedHandler(new CommonServerAccessDeniedHandler());

        http.authorizeExchange().pathMatchers(
                "/actuator/**",
                "/v3/api-docs/**",
                "/swagger-ui/**",
                "/swagger-ui.html",
                "/webjars/swagger-ui/**",
                "/favicon.ico").permitAll()
            .anyExchange().authenticated();
        // @formatter:on

        http.redirectToHttps();

        return http.build();
    }

    @Bean
    public WebFluxConfigurer corsConfigurer() {
        return new WebFluxConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping(corsPath)
                        .allowedOrigins("http://localhost", "https://localhost", "https://bravo-ch4mp:8100", "https://bravo-ch4mp:4200")
                        .allowedMethods("*")
                        .exposedHeaders("Origin", "Accept", "Content-Type", "Location");
            }

        };
    }

    protected ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorize(
            ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry) {
        return registry.antMatchers("/actuator/**", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll().anyRequest().authenticated();
    }
}
