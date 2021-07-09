package com.c4_soft.lifix.persistence;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.r2dbc.convert.R2dbcCustomConversions;

import com.c4_soft.lifix.persistence.intervention.FaultAttachmentRepo.FaulAttachmenttWritingConverter;
import com.c4_soft.lifix.persistence.intervention.FaultAttachmentRepo.FaultAttachmentReadingConverter;
import com.c4_soft.lifix.persistence.intervention.FaultRepo.FaultReadingConverter;
import com.c4_soft.lifix.persistence.intervention.FaultRepo.FaultWritingConverter;
import com.c4_soft.lifix.persistence.user.LifixUserRepo.LifixUserReadingConverter;
import com.c4_soft.lifix.persistence.user.LifixUserRepo.LifixUserWritingConverter;

@Configuration
public class R2dbcConfig {

    @Bean
    protected R2dbcCustomConversions getCustomConverters() {
        return new R2dbcCustomConversions(
                List.of(
                        new FaultReadingConverter(),
                        new FaultWritingConverter(),
                        new FaultAttachmentReadingConverter(),
                        new FaulAttachmenttWritingConverter(),
                        new LifixUserReadingConverter(),
                        new LifixUserWritingConverter()));
    }
}