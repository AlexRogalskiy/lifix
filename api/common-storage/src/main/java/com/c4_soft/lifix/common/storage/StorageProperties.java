package com.c4_soft.lifix.common.storage;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

@Data
@ConfigurationProperties("com.c4-soft.storage")
@Component
public class StorageProperties {

    private String rootPath;

}
