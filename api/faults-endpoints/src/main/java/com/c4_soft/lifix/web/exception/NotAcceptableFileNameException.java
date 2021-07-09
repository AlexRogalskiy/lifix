package com.c4_soft.lifix.web.exception;

public class NotAcceptableFileNameException extends RuntimeException {
    private static final long serialVersionUID = 1649623586303850916L;

    public NotAcceptableFileNameException(String fileName) {
        super("provided files must have an extension but got: " + fileName);
    }
}