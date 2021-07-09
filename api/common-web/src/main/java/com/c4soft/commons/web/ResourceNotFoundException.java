package com.c4soft.commons.web;

public class ResourceNotFoundException extends RuntimeException {
    private static final long serialVersionUID = 5420090598360902565L;

    public ResourceNotFoundException(String message) {
        super(message);
    }
}
