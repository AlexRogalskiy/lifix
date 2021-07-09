package com.c4_soft.lifix.common.storage;

public class StorageException extends RuntimeException {
    private static final long serialVersionUID = 1698010272886403332L;

    public StorageException(String message) {
        super(message);
    }

    public StorageException(String message, Throwable cause) {
        super(message, cause);
    }
}
