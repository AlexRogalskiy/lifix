package com.c4_soft.lifix.common.storage;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.stereotype.Service;
import org.springframework.util.FileSystemUtils;

import lombok.extern.java.Log;
import reactor.core.publisher.Mono;

@Service
@Log
public class FileSystemStorageService implements StorageService {

    private final Path rootPath;

    @Autowired
    public FileSystemStorageService(StorageProperties properties) throws URISyntaxException, IOException {
        final var workingDir = Files.createTempDirectory(null).resolve(properties.getRootPath());
        log.info("workingDir: " + workingDir);
        this.rootPath = workingDir;
    }

    @Override
    public Mono<Void> store(FilePart file, String relativePath) {
        return file.transferTo(this.rootPath.resolve(relativePath));
    }

    @Override
    public Stream<Path> loadAll() {
        try {
            return Files.walk(this.rootPath, 1).filter(path -> !path.equals(this.rootPath)).map(path -> this.rootPath.relativize(path));
        } catch (IOException e) {
            throw new StorageException("Failed to read stored files", e);
        }

    }

    @Override
    public Resource loadAsResource(String relativePath) {
        try {
            var file = rootPath.resolve(relativePath);
            Resource resource = new UrlResource(file.toUri());
            if (resource.exists() || resource.isReadable()) {
                return resource;
            }
            throw new StorageFileNotFoundException("Could not read file: " + relativePath);
        } catch (MalformedURLException e) {
            throw new StorageFileNotFoundException("Could not read file: " + relativePath, e);
        }
    }

    @Override
    public boolean delete(String relativePath) {
        var path = rootPath.resolve(relativePath);
        return FileSystemUtils.deleteRecursively(path.toFile());
    }

    @Override
    public boolean deleteAll() {
        return FileSystemUtils.deleteRecursively(rootPath.toFile());
    }

    @Override
    public boolean init() {
        try {
            return Files.createDirectory(rootPath) != null;
        } catch (IOException e) {
            throw new StorageException("Could not initialize storage", e);
        }
    }

}
