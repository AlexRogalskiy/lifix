package com.c4_soft.lifix.web.dto;

import java.net.URI;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FaultResponseDto {

    private URI uri;

    private String description;

    private String openedBy;

    private Long openedAt;

    private String closedBy;

    private Long closedAt;

    private List<URI> attachments;

}
