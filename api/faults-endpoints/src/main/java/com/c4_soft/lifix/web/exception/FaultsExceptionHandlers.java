package com.c4_soft.lifix.web.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import lombok.extern.java.Log;

@ControllerAdvice
@Log
public class FaultsExceptionHandlers {

    @ExceptionHandler(NotAcceptableFileNameException.class)
    public ResponseEntity<String> handle(NotAcceptableFileNameException e) {
        log.info(e.getMessage());
        return ResponseEntity.badRequest().body(e.getMessage());
    }

    @ExceptionHandler(EmptyDescriptionException.class)
    public ResponseEntity<String> handle(EmptyDescriptionException e) {
        log.info(e.getMessage());
        return ResponseEntity.badRequest().body(e.getMessage());
    }

}
