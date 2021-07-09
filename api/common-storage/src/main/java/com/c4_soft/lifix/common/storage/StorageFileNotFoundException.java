package com.c4_soft.lifix.common.storage;

public class StorageFileNotFoundException extends StorageException {
    private static final long serialVersionUID = 90631947709899564L;

    public StorageFileNotFoundException(String message) {
        super(message);
    }

    public StorageFileNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
