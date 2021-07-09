package com.c4_soft.lifix.web;

import java.net.URI;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;

import com.c4_soft.lifix.common.storage.StorageService;
import com.c4_soft.lifix.domain.intervention.Fault;
import com.c4_soft.lifix.domain.intervention.FaultAttachment;
import com.c4_soft.lifix.persistence.intervention.FaultAttachmentRepo;
import com.c4_soft.lifix.persistence.intervention.FaultRepo;
import com.c4_soft.lifix.web.dto.FaultEditDto;
import com.c4_soft.lifix.web.dto.FaultResponseDto;
import com.c4_soft.lifix.web.exception.EmptyDescriptionException;
import com.c4_soft.lifix.web.exception.NotAcceptableFileNameException;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdAuthenticationToken;
import com.c4soft.commons.web.ResourceNotFoundException;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/faults")
@RequiredArgsConstructor
@PreAuthorize("isAuthenticated()")
public class FaultController {
    private final StorageService storageService;
    private final FaultRepo faultRepo;
    private final FaultAttachmentRepo attachmentRepo;

    @PostMapping()
    @PreAuthorize("hasAuthority('FAULT_EDITOR')")
    public Mono<ResponseEntity<Void>> create(@RequestBody FaultEditDto dto, ServerHttpRequest req, OidcIdAuthenticationToken auth) {
        if (!StringUtils.hasText(dto.getDescription())) {
            throw new EmptyDescriptionException();
        }

        final var fault = new Fault(auth.getName(), dto.getDescription().trim());
        if (dto.isClosed()) {
            fault.setClosedBy(auth.getName());
            fault.setClosedAt(new Date());
        }
        return faultRepo.save(fault).map(saved -> {
            final var uri = req.getURI().resolve(saved.getId().toString());
            return ResponseEntity.created(uri).build();
        });
    }

    @GetMapping()
    public Flux<FaultResponseDto> retrieveMany(
            @RequestParam(required = false, defaultValue = "false") boolean isClosedIncluded,
            ServerHttpRequest req,
            OidcIdAuthenticationToken auth) {
        final var faults = isClosedIncluded ? faultRepo.findAll() : faultRepo.findOpened();
        return faults.flatMap(fault -> toDto(fault, req.getURI()));
    }

    @GetMapping("/{faultId}")
    public Mono<FaultResponseDto> retrieveById(@PathVariable("faultId") Long faultId, ServerHttpRequest req) {
        return faultRepo.findById(faultId)
                .flatMap(fault -> toDto(fault, req.getURI().resolve("..")))
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("no fault with id " + faultId)));
    }

    @Transactional
    @PutMapping("/{faultId}")
    @PreAuthorize("hasAuthority('FAULT_EDITOR')")
    public Mono<ResponseEntity<Object>> update(
            @PathVariable("faultId") Long faultId,
            @RequestBody FaultEditDto dto,
            ServerHttpRequest req,
            OidcIdAuthenticationToken auth) {
        return faultRepo.findById(faultId).flatMap(fault -> {
            fault.setDescription(dto.getDescription());
            if (dto.isClosed() && fault.getClosedBy() == null) {
                fault.setClosedAt(new Date());
                fault.setClosedBy(auth.getName());
            } else if (!dto.isClosed()) {
                fault.setClosedAt(null);
                fault.setClosedBy(null);
            }
            return faultRepo.save(fault).map(f -> ResponseEntity.accepted().build());
        }).switchIfEmpty(Mono.just(ResponseEntity.notFound().build()));
    }

    @DeleteMapping("/{faultId}")
    @PreAuthorize("hasAuthority('FAULT_EDITOR')")
    public Mono<ResponseEntity<Void>> delete(@PathVariable("faultId") Long faultId) {
        return attachmentRepo.deleteById(faultId).then(faultRepo.deleteById(faultId)).then(Mono.just(ResponseEntity.accepted().build()));
    }

    @Transactional
    @PostMapping(path = "/{faultId}/attachments", consumes = { "multipart/form-data" })
    @PreAuthorize("hasAuthority('FAULT_EDITOR')")
    public Mono<ResponseEntity<Object>> createAttachment(
            @PathVariable("faultId") Long faultId,
            @RequestPart("attachment") FilePart file,
            ServerHttpRequest req,
            OidcIdAuthenticationToken auth) {
        final var fileName = file.filename();
        if (!fileName.contains(".") || fileName.endsWith(".")) {
            throw new NotAcceptableFileNameException(fileName);
        }
        return faultRepo.findById(faultId).flatMap(fault -> {
            final var saved = attachmentRepo.save(new FaultAttachment(fault.getId(), fileName.substring(fileName.lastIndexOf(".") + 1)));
            return saved.flatMap(attachment -> storageService.store(file, relativePath(attachment)).thenReturn(attachment));
        })
                .map(attachment -> ResponseEntity.created(uri(req.getURI().resolve(".."), attachment)).build())
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("no fault with id " + faultId)));
    }

    @GetMapping("/{faultId}/attachments/{attachmentName}")
    public Mono<Resource> retrieveAttachmentById(@PathVariable("faultId") Long faultId, @PathVariable("attachmentName") String attachmentName) {
        final var attachmentParts = attachmentName.split("\\.");
        if (attachmentParts.length != 2) {
            throw new NotAcceptableFileNameException(attachmentName);
        }
        return attachmentRepo.findById(Long.parseLong(attachmentParts[0])).flatMap(attachment -> {
            if (!attachment.getFaultId().equals(faultId)) {
                throw new ResourceNotFoundException("attachment with name " + attachmentName + " for fault " + faultId.toString());
            }
            return Mono.just(storageService.loadAsResource(relativePath(attachment)));
        });
    }

    @DeleteMapping("/{faultId}/attachments/{attachmentName}")
    @PreAuthorize("hasAuthority('FAULT_EDITOR')")
    public Mono<ResponseEntity<Object>> deleteAttachment(@PathVariable("faultId") Long faultId, @PathVariable("attachmentName") String attachmentName) {
        final var attachmentParts = attachmentName.split("\\.");
        if (attachmentParts.length != 2) {
            throw new NotAcceptableFileNameException(attachmentName);
        }
        return attachmentRepo.findById(Long.parseLong(attachmentParts[0])).map(attachment -> {
            storageService.delete(relativePath(attachment));
            return storageService.delete(relativePath(attachment));
        }).map(isDeleted -> ResponseEntity.accepted().build()).switchIfEmpty(Mono.error(new ResourceNotFoundException("no fault with id " + faultId)));
    }

    Mono<FaultResponseDto> toDto(Fault fault, URI faultsUri) {
        return attachmentRepo.findByFaultId(fault.getId()).collectList().map(attachments -> {
            final var attachmentUris = attachments.stream().map(attachment -> uri(faultsUri, attachment)).collect(Collectors.toList());
            final var dto =
                    FaultResponseDto.builder()
                            .uri(faultsUri.resolve("faults/" + fault.getId().toString()))
                            .description(fault.getDescription())
                            .openedBy(fault.getOpenedBy())
                            .openedAt(fault.getOpenedAt().getTime())
                            .closedBy(fault.getClosedBy())
                            .closedAt(Optional.ofNullable(fault.getClosedAt()).map(Date::getTime).orElse(null))
                            .attachments(attachmentUris);
            return dto.build();
        });
    }

    static String relativePath(FaultAttachment attachment) {
        return attachment.getFaultId().toString() + "/" + attachment.getId().toString() + "." + attachment.getExtension();
    }

    static URI uri(URI faultsUri, FaultAttachment attachment) {
        return faultsUri.resolve("faults/" + attachment.getFaultId().toString() + "/attachments/" + attachment.getId() + "." + attachment.getExtension());
    }
}
