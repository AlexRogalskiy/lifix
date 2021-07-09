package com.c4soft.commons.web;

public class MissingRequiredArgumentException extends RuntimeException {
    private static final long serialVersionUID = 1212439197068161287L;

    public MissingRequiredArgumentException(String message) {
        super(message);
    }

}
