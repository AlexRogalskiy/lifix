package com.c4_soft.lifix.domain.intervention;

import java.util.Date;

import org.springframework.data.annotation.Id;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Fault {
    @Id
    Long id;

    String description;

    final String openedBy;

    final Date openedAt;

    String closedBy;

    Date closedAt;

    public Fault(String openerSubject, String description) {
        this(null, description, openerSubject, new Date(), null, null);
    }

    Fault() {
        this(null, null);
    }

}
