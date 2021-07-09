package com.c4_soft.lifix.web.exception;

public class EmptyDescriptionException extends RuntimeException {
    private static final long serialVersionUID = 1649623586303850916L;

    public EmptyDescriptionException() {
        super("fault description can't be empty");
    }
}