package com.c4_soft.lifix.persistence.intervention;

import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.convert.WritingConverter;
import org.springframework.data.r2dbc.mapping.OutboundRow;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveSortingRepository;
import org.springframework.r2dbc.core.Parameter;
import org.springframework.stereotype.Repository;

import com.c4_soft.lifix.domain.intervention.FaultAttachment;

import io.r2dbc.spi.Row;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Repository
public interface FaultAttachmentRepo extends ReactiveSortingRepository<FaultAttachment, Long> {

    @Query("SELECT * FROM fault_attachment WHERE fault_id = :faultId")
    Flux<FaultAttachment> findByFaultId(long faultId);

    @Query("DEMLETE * FROM fault_attachment WHERE fault_id = :faultId")
    Mono<Void> deleteByFaultId(long faultId);

    @ReadingConverter
    public static class FaultAttachmentReadingConverter implements Converter<Row, FaultAttachment> {

        @Override
        public FaultAttachment convert(Row source) {
            return new FaultAttachment(source.get("id", Long.class), source.get("fault_id", Long.class), source.get("extension", String.class));
        }
    }

    @WritingConverter
    public static class FaulAttachmenttWritingConverter implements Converter<FaultAttachment, OutboundRow> {

        @Override
        public OutboundRow convert(FaultAttachment source) {
            var row = new OutboundRow();
            row.put("id", Parameter.from(source.getId()));
            row.put("fault_id", Parameter.from(source.getFaultId()));
            row.put("extension", Parameter.from(source.getExtension()));
            return row;
        }
    }
}
