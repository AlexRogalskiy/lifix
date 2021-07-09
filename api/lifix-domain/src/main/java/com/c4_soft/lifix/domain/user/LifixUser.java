package com.c4_soft.lifix.domain.user;

import org.springframework.data.annotation.Id;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@AllArgsConstructor
@Builder
public class LifixUser {
    /**
     * User OpenID subject
     */
    @Id
    final String sub;

    String email;

    String userName;
}