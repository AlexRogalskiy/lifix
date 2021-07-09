package com.c4soft.commons.security;

import java.nio.charset.Charset;

import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

public class CommonServerAccessDeniedHandler implements ServerAccessDeniedHandler {

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException ex) {
        return exchange.getPrincipal().flatMap(principal -> {
            final var response = exchange.getResponse();
            response.setStatusCode(principal instanceof AnonymousAuthenticationToken ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN);
            response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
            var dataBufferFactory = response.bufferFactory();
            var buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
            return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
        });
    }

}