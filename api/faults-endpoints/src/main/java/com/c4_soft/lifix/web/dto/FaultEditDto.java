package com.c4_soft.lifix.web.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class FaultEditDto {

    private String description;

    private boolean isClosed = false;

}
