package com.c4_soft.lifix.common.storage;

import java.nio.file.Path;
import java.util.stream.Stream;

import org.springframework.core.io.Resource;
import org.springframework.http.codec.multipart.FilePart;

import reactor.core.publisher.Mono;

public interface StorageService {

    boolean init();

    Mono<Void> store(FilePart file, String relativePath);

    Stream<Path> loadAll();

    Resource loadAsResource(String relativePath);

    boolean delete(String relativePath);

    boolean deleteAll();

}
