package com.c4_soft.lifix.domain.intervention;

import org.springframework.data.annotation.Id;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class FaultAttachment {
    @Id
    Long id;

    Long faultId;

    String extension;

    public FaultAttachment(Long faultId, String extension) {
        this(null, faultId, extension);
    }

}
