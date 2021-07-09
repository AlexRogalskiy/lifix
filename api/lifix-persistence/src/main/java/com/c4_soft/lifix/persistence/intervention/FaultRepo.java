package com.c4_soft.lifix.persistence.intervention;

import java.util.Date;
import java.util.Optional;

import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.convert.WritingConverter;
import org.springframework.data.r2dbc.mapping.OutboundRow;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveSortingRepository;
import org.springframework.r2dbc.core.Parameter;
import org.springframework.stereotype.Repository;

import com.c4_soft.lifix.domain.intervention.Fault;

import io.r2dbc.spi.Row;
import reactor.core.publisher.Flux;

@Repository
public interface FaultRepo extends ReactiveSortingRepository<Fault, Long> {

    @Query("SELECT * FROM fault WHERE closed_on IS NULL")
    Flux<Fault> findOpened();

    @ReadingConverter
    public static class FaultReadingConverter implements Converter<Row, Fault> {

        @Override
        public Fault convert(Row source) {
            return new Fault(
                    source.get("id", Long.class),
                    source.get("desription", String.class),
                    source.get("opened_by", String.class),
                    new Date(source.get("opened_on", Long.class)),
                    source.get("closed_by", String.class),
                    Optional.ofNullable(source.get("closed_on", Long.class)).map(Date::new).orElse(null));
        }
    }

    @WritingConverter
    public static class FaultWritingConverter implements Converter<Fault, OutboundRow> {

        @Override
        public OutboundRow convert(Fault source) {
            var row = new OutboundRow();
            if (source.getId() != null) {
                row.put("id", Parameter.from(source.getId()));
            }
            row.put("desription", Parameter.from(source.getDescription()));
            row.put("opened_by", Parameter.from(source.getOpenedBy()));
            row.put("opened_on", Parameter.from(source.getOpenedAt().getTime()));
            Optional.of(source.getClosedBy()).ifPresent(closedBy -> row.put("closed_by", Parameter.from(closedBy)));
            Optional.of(source.getClosedAt()).ifPresent(closedAt -> row.put("closed_on", Parameter.from(closedAt.getTime())));
            return row;
        }
    }
}
