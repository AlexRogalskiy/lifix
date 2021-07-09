package com.c4_soft.lifix.persistence.user;

import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.convert.WritingConverter;
import org.springframework.data.r2dbc.mapping.OutboundRow;
import org.springframework.data.repository.reactive.ReactiveSortingRepository;
import org.springframework.r2dbc.core.Parameter;
import org.springframework.stereotype.Repository;

import com.c4_soft.lifix.domain.user.LifixUser;

import io.r2dbc.spi.Row;

@Repository
public interface LifixUserRepo extends ReactiveSortingRepository<LifixUser, Long> {

    @ReadingConverter
    public static class LifixUserReadingConverter implements Converter<Row, LifixUser> {

        @Override
        public LifixUser convert(Row source) {
            return new LifixUser(source.get("subject", String.class), source.get("email", String.class), source.get("username", String.class));
        }
    }

    @WritingConverter
    public static class LifixUserWritingConverter implements Converter<LifixUser, OutboundRow> {

        @Override
        public OutboundRow convert(LifixUser source) {
            var row = new OutboundRow();
            row.put("subject", Parameter.from(source.getSub()));
            row.put("email", Parameter.from(source.getEmail()));
            row.put("username", Parameter.from(source.getUserName()));
            return row;
        }
    }

}
