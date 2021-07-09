package com.c4soft.commons.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

import lombok.extern.java.Log;

@ControllerAdvice
@Log
public class CommonExceptionHandlers {

    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ExceptionHandler(ResourceNotFoundException.class)
    protected ResponseEntity<Void> handleResourceNotFound(ResourceNotFoundException e) {
        log.info(e.getMessage());
        return ResponseEntity.notFound().build();
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(MissingRequiredArgumentException.class)
    protected ResponseEntity<String> handleMissingRequiredArgument(MissingRequiredArgumentException e) {
        log.info(e.getMessage());
        return ResponseEntity.badRequest().body(e.getMessage());
    }
}
